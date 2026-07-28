# Treasury Contract

The `treasury` contract is the fee accumulator for the Kora Protocol. It receives protocol fees from the marketplace, maintains an accounting ledger per token, and provides admin-controlled withdrawal with reentrancy protection and a rolling rate-limit.

---

## Role in Kora Protocol

The treasury sits at the end of the fee flow:

```
investor → marketplace (fund_invoice)
               ├── fee  →  treasury.collect_fee()
               └── net  →  financing_pool
```

The marketplace transfers the fee amount directly to the treasury's token balance and then calls `collect_fee()` to update the informational ledger. The treasury itself never pulls funds — it only receives them.

---

## Fee Model

### fee_bps lifecycle

`fee_bps` (basis points, 0–10 000) is the protocol's cut of every investor contribution.

| Event | Who acts | Effect |
|-------|----------|--------|
| `initialize(admin, fee_bps)` | Deployer | Sets initial rate; stored in persistent storage |
| `set_fee_bps(admin, fee_bps)` | Admin | Updates rate; emits `FeeRateUpdated` event |
| `fund_invoice(investor, …)` on Marketplace | Investor | `fee = amount × fee_bps / 10_000` deducted before net reaches pool |

**Default:** 50 bps (0.5 %).

**Bound:** 0–10 000 bps (0 % – 100 %). Values outside this range are rejected with `InvalidFeeRate`.

Fee math uses `bps_of` from `kora_shared::validation` — integer arithmetic only, no floats. Overflow returns `ArithmeticOverflow`.

### Token whitelisting

Only tokens whitelisted by the admin via `whitelist_token()` can be used in `collect_fee()`, `withdraw()`, and `emergency_withdraw()`. Attempting to use a non-whitelisted token returns `TokenNotWhitelisted`.

### Accounting ledger (`Collected`)

`Collected(token_address) → i128` tracks the cumulative fees received per token. It is informational — the authoritative balance is always the live token balance returned by `get_balance()`. The ledger is decremented on successful withdrawal.

---

## Withdrawal Flows

### `withdraw(admin, token, recipient, amount)`

Normal fee withdrawal. Steps (in order):

1. `admin.require_auth()` — transaction must be signed by the admin
2. Admin identity check — `require_admin()`
3. Amount validation — must be > 0 and ≤ `MAX_AMOUNT`
4. Token whitelist check — `require_whitelisted_token()`
5. Rate-limit check — `enforce_rate_limit()` (see below)
6. **Acquire reentrancy guard** — `ReentrancyGuard::new(&env)?`
7. Balance check — live token balance must be ≥ `amount`
8. Decrement `Collected` ledger
9. Record withdrawal against the current epoch (`record_withdrawal()`)
10. Token transfer: `contract → recipient`
11. Emit `FeeWithdrawn` event

Errors: `NotAdmin`, `InvalidAmount`, `TokenNotWhitelisted`, `WithdrawalRateLimitExceeded`, `Reentrancy`, `InsufficientPoolBalance`.

### `emergency_withdraw(admin, token, recipient)`

Drains the entire token balance in one call. Used in crisis scenarios. Steps:

1. `admin.require_auth()`
2. Admin identity check
3. Token whitelist check
4. **Emergency declared check** — `EmergencyDeclared` must be `true` (see below)
5. **Acquire reentrancy guard**
6. Read live balance
7. If balance > 0: transfer full balance to recipient and emit `EmergencyWithdrawn`
8. If balance = 0: silent no-op (not an error)

Note: `emergency_withdraw` does **not** enforce the rolling rate-limit — it is intentionally unrestricted for emergency use. The reentrancy guard still applies.

**Emergency declaration gate (#453):** Prior to this fix, `emergency_withdraw` was callable at any time by the admin, making the rolling withdrawal cap on `withdraw` fully bypassable — a compromised admin key could simply call `emergency_withdraw` instead of `withdraw` and drain the full balance in one transaction. `emergency_withdraw` is now gated behind a distinct, auditable `EmergencyDeclared` flag:

```
declare_emergency(admin)   // sets EmergencyDeclared = true, audited + evented
emergency_withdraw(...)    // now callable
revoke_emergency(admin)    // sets EmergencyDeclared = false, re-locking the drain path
```

This gate is deliberately **independent of the protocol-wide pause flag**. `emergency_withdraw` exists to evacuate funds during an incident — exactly when the protocol is most likely to already be paused — so tying it to `!is_paused()` would make it unusable precisely when needed. `withdraw`, by contrast, *is* blocked while paused (see "Pause Enforcement" below).

---

## Reentrancy Protection

Both `withdraw` and `emergency_withdraw` acquire a RAII `ReentrancyGuard` before touching funds. The guard is implemented in `kora_shared::reentrancy`:

- Sets a `GuardKey::Lock` flag in instance storage on acquire
- Clears it in the `Drop` implementation, guaranteeing release even on early returns or panics
- Any re-entrant call into a guarded function returns `KoraError::Reentrancy` (discriminant 98)

The guard is acquired **after** all authorization and validation checks, so failed checks never leave the lock set.

---

## Rolling Withdrawal Rate-Limit

To cap the blast radius of a compromised admin key, withdrawals are subject to a configurable 24-hour rolling cap — **tracked independently per whitelisted token (#452)**.

| Storage key | Type | Default | Meaning |
|-------------|------|---------|---------|
| `WithdrawalCap(token)` | `i128` | `0` | Max withdrawable per 24 h epoch, for this token. `0` = uncapped |
| `EpochStart(token)` | `u64` | first withdrawal time | Timestamp of this token's current epoch start |
| `EpochWithdrawn(token)` | `i128` | `0` | Amount withdrawn so far in this token's current epoch |

Exhausting Token A's cap has no effect on Token B's quota — each token has its own independent rolling cap and epoch, since fee accounting (`Collected(Address)`) is already per-token and unrelated tokens carry unrelated risk profiles and unit values.

**Epoch reset:** if `now − EpochStart(token) ≥ 86 400 s`, that token's epoch counters reset automatically at its next withdrawal.

**Changing the cap** uses a two-step timelock, per token:

```
propose_withdrawal_cap(admin, token, new_cap)   // stores (new_cap, timestamp) for `token`
// wait ≥ UPGRADE_TIMELOCK_DELAY seconds
execute_withdrawal_cap(admin, token)            // applies new_cap for `token`
```

Executing before the timelock elapses returns `WithdrawalCapTimelockNotElapsed`. Executing without a pending proposal returns `NoCapChangeProposed`.

**Migration note:** this replaced a single global `WithdrawalCap`/`EpochStart`/`EpochWithdrawn`. There is no automatic carry-over of a prior global cap value to any specific token — every whitelisted token defaults to **uncapped** (`0`) until the admin explicitly proposes and executes a per-token cap for it via the flow above. Operators relying on the previous global cap for blast-radius protection must re-configure a cap for each whitelisted token after upgrading.

---

## Pause Enforcement (#454)

Treasury can optionally be wired to the protocol's `access_control` contract:

```
set_access_control(admin, access_control)   // one-time or updatable admin setter
```

Once set, `withdraw` calls `require_not_paused()` and is rejected with `KoraError::ProtocolPaused` while the protocol is paused. If `access_control` has never been configured (e.g. a test environment), the pause check is skipped rather than erroring.

| Function | Blocked while paused? |
|----------|------------------------|
| `withdraw` | Yes |
| `emergency_withdraw` | No — gated instead by `EmergencyDeclared` (see above); intentionally independent of the pause flag so the emergency path remains usable during an incident |
| `collect_fee` | No (intentionally exempt) — it is only ever invoked mid-transaction by `marketplace.fund_invoice`, which already gates its own entry point with its own `require_not_paused`. Re-checking here would let a treasury-only pause silently break marketplace's funding flow for no added security benefit, mirroring the documented pause exceptions for repayment paths in `invoice_nft` / `financing_pool`. |

---

## Contract Upgrade

`propose_upgrade(admin, new_wasm_hash)` + `execute_upgrade(admin)` follow the same two-step timelock pattern. The upgrade is applied via `env.deployer().update_current_contract_wasm()` only after `UPGRADE_TIMELOCK_DELAY` has elapsed.

---

## Public API

| Function | Auth | Description |
|----------|------|-------------|
| `initialize(admin, fee_bps)` | None (one-time) | Set admin and fee rate |
| `set_fee_bps(admin, fee_bps)` | Admin | Update protocol fee |
| `set_access_control(admin, access_control)` | Admin | Wire up pause enforcement (#454) |
| `whitelist_token(admin, token)` | Admin | Allow token for fee operations |
| `collect_fee(token, amount)` | None | Record incoming fee (called by marketplace) |
| `withdraw(admin, token, recipient, amount)` | Admin | Withdraw fees with rate-limit; blocked while paused |
| `emergency_withdraw(admin, token, recipient)` | Admin | Drain full balance; requires `declare_emergency` first |
| `declare_emergency(admin)` | Admin | Unlock `emergency_withdraw` (#453) |
| `revoke_emergency(admin)` | Admin | Re-lock `emergency_withdraw` |
| `is_emergency_declared()` | None | Whether emergency mode is currently declared |
| `is_paused()` | None | Whether this treasury sees the protocol as paused |
| `propose_withdrawal_cap(admin, token, new_cap)` | Admin | Propose new per-token 24 h cap (#452) |
| `execute_withdrawal_cap(admin, token)` | Admin | Apply per-token cap after timelock |
| `get_fee_bps()` | None | Read current fee rate |
| `get_balance(token)` | None | Live token balance |
| `get_collected(token)` | None | Informational ledger total |
| `get_withdrawal_cap(token)` | None | Current per-token 24 h cap (0 = uncapped) |
| `get_admin()` | None | Current admin address |
| `propose_upgrade(admin, wasm_hash)` | Admin | Propose contract upgrade |
| `execute_upgrade(admin)` | Admin | Apply upgrade after timelock |

---

## Storage Layout

| Key | Tier | Type | Description |
|-----|------|------|-------------|
| `Admin` | persistent | `Address` | Admin address |
| `FeeBps` | persistent | `u32` | Protocol fee rate |
| `Collected(Address)` | persistent | `i128` | Cumulative fees per token |
| `WhitelistedToken(Address)` | persistent | `bool` | Token whitelist flag |
| `UpgradeProposal` | instance | `(BytesN<32>, u64)` | Pending upgrade hash + timestamp |
| `WithdrawalCap(Address)` | instance | `i128` | 24 h withdrawal cap, per token (#452) |
| `WithdrawalCapProposal(Address)` | instance | `(i128, u64)` | Pending cap change + timestamp, per token |
| `EpochStart(Address)` | instance | `u64` | Current epoch start timestamp, per token |
| `EpochWithdrawn(Address)` | instance | `i128` | Amount withdrawn in current epoch, per token |
| `AccessControl` | instance | `Address` | Optional `access_control` reference for pause enforcement (#454) |
| `EmergencyDeclared` | instance | `bool` | Gate for `emergency_withdraw` (#453) |

Persistent entries are TTL-bumped to ~31 days (`535 680` ledgers) on every write. Instance storage is tied to the contract instance and does not expire independently.

---

## Security Analysis

### Threat: stolen admin key

**Mitigations in place:**
- Rolling 24 h withdrawal cap limits the maximum extractable amount per epoch, per token (#452)
- Cap changes require a timelock — an attacker cannot immediately raise the cap
- Contract upgrades require a timelock — an attacker cannot swap in malicious code immediately
- `withdraw` is blocked while the protocol is paused (#454), giving admins a way to halt fund egress on detection
- `emergency_withdraw` — previously always callable, which fully bypassed the rate-limit cap — now requires a distinct, auditable `declare_emergency` call first (#453)

**Residual risk:** with a token's cap disabled (`WithdrawalCap(token) = 0`), a compromised key can drain that token's full balance in one transaction via `withdraw`, and any whitelisted token's balance via `emergency_withdraw` once `declare_emergency` has been called (by design, `declare_emergency`/`emergency_withdraw` share the single admin key rather than a stronger multisig — see #453's acceptance criteria for the multisig follow-up this doesn't yet cover). Per-token caps should always be set in production, and `access_control` should be configured via `set_access_control`.

### Threat: reentrancy via malicious token

A Soroban token transfer could theoretically re-enter the treasury. The `ReentrancyGuard` blocks this: any re-entrant call to `withdraw` or `emergency_withdraw` hits the locked guard and returns `Reentrancy` (discriminant 98) before touching state.

### Threat: silent misreporting of errors

Prior to fix #343, `KoraError::Reentrancy` shared discriminant 95 with another variant, causing reentrancy errors to be decoded as a different error by off-chain clients. This is fixed — `Reentrancy` is now discriminant 98, unique across the enum.

### Threat: non-whitelisted token drain

`require_whitelisted_token()` is checked before any fund movement. Tokens not added by the admin cannot be referenced in fee or withdrawal calls.

### Invariants

1. `fee_bps` is always in `[0, 10_000]`.
2. The reentrancy lock is always released — either by `Drop` on success or on any error path.
3. `emergency_withdraw` never reverts on zero balance.
4. Withdrawals only succeed if the live token balance covers the requested amount.
5. The `Collected` ledger is informational only — it never gates withdrawals.
