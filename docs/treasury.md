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

Errors: `NotAdmin`, `InvalidAmount`, `TokenNotWhitelisted`, `RecipientNotAllowed`, `WithdrawalRateLimitExceeded`, `Reentrancy`, `InsufficientPoolBalance`, `QuorumRequired`.

The live balance check excludes any amount earmarked in the token's loss reserve (see
[Insurance / Loss Reserve](#insurance--loss-reserve) below) — reserve funds are never
withdrawable through this path.

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

Note: `emergency_withdraw` does **not** enforce the rolling rate-limit — it is intentionally unrestricted for emergency use. The reentrancy guard still applies. Like `withdraw`, it drains only the *spendable* balance (live balance minus the token's reserve balance) and requires `recipient` to be on the allowlist.

---

## Recipient Allowlist & Timelock

`withdraw` and `emergency_withdraw` only ever send funds to a pre-registered, timelock-matured
`recipient`. This closes the gap where a compromised admin key could redirect funds to an
attacker-chosen address in the same transaction — only the *amount* was previously rate-limited,
never the *destination*.

```
propose_recipient(admin, recipient)   // stores proposed_at timestamp
// wait ≥ UPGRADE_TIMELOCK_DELAY seconds
execute_recipient(admin, recipient)   // adds recipient to the allowlist
```

`is_recipient_allowed(recipient)` is a read-only view. Executing before the timelock elapses
returns `RecipientTimelockNotElapsed`; executing without a pending proposal returns
`NoRecipientProposed`; withdrawing to a non-allowlisted address returns `RecipientNotAllowed`.

---

## Insurance / Loss Reserve

A configurable portion of every fee recorded via `collect_fee` is earmarked into a per-token
loss reserve instead of the freely admin-withdrawable pool, so the same investor contributions
that fund the protocol fee can also partially backstop investor losses on a recorded default.

| Function | Auth | Description |
|----------|------|-------------|
| `set_reserve_allocation_bps(admin, bps)` | Admin | Portion (0–10 000 bps) of new fees routed to the reserve |
| `set_reserve_caller(admin, caller, authorized)` | Admin | Authorize/deauthorize an address (e.g. `financing_pool`) to draw down the reserve |
| `disburse_from_reserve(caller, token, amount, recipient)` | Authorized caller | Pay `amount` from the token's reserve to `recipient` |
| `get_reserve_balance(token)` | None | Current reserve balance for `token` |
| `get_reserve_allocation_bps()` | None | Current allocation rate |
| `is_reserve_caller(caller)` | None | Whether `caller` is authorized |

Reserve funds are tracked in `ReserveBalance(token)`, a subset of the live token balance that is
excluded from `withdraw`/`emergency_withdraw`'s spendable amount — the admin can never touch
reserve-earmarked funds through the normal withdrawal path. `disburse_from_reserve` requires a
genuine `caller.require_auth()` (a contract-to-contract auth check, since `financing_pool` calls
it programmatically) and rejects unauthorized callers (`ReserveCallerNotAuthorized`) or amounts
exceeding the reserve balance (`InsufficientReserveBalance`).

---

## Multisig Quorum Gate

Treasury's highest-risk functions — `withdraw`, `emergency_withdraw`, `set_fee_bps`, and
`propose_upgrade` — can be linked to an `access_control` deployment's multisig via
`set_access_control(admin, access_control)`. Once that `access_control` has a multisig configured
with `threshold > 1`, those four functions can no longer be called directly (they return
`QuorumRequired`); callers must instead go through:

```
propose_treasury_action(proposer, action)     // proposer must be a configured signer; auto-approves
approve_treasury_action(approver, proposal_id) // any other signer who hasn't yet voted
execute_treasury_action(executor, proposal_id) // once approvals >= access_control's threshold
```

`action` is a `TreasuryAction` (`Withdraw`, `EmergencyWithdraw`, `SetFeeBps`, or `ProposeUpgrade`)
carrying the same parameters the direct call would have taken. Deployments that never call
`set_access_control`, or link to an `access_control` with no multisig (or a 1-of-1 "multisig"),
keep working exactly as before — this is the backward-compatible, single-signer degenerate case.
`get_treasury_proposal(proposal_id)` is a read-only view of a pending or executed proposal.

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

## Cross-Currency Fee Valuation (Price Oracle Integration)

As the protocol whitelists multiple stablecoins (e.g., USDC, EURC), the treasury can now calculate total fee revenue in a single common currency using the price oracle.

### `set_price_oracle(admin, price_oracle)`

Sets or updates the price oracle contract address. Optional — if not set, conversion-based views will return 0.

- **Auth:** Admin only (`require_auth()`)
- **Parameters:** `price_oracle` (Address)
- **Returns:** None
- **Errors:** `NotAdmin` if caller is not the admin

### `get_total_collected_value(tokens, token_symbols, reference_currency, token_decimals, ref_decimals)`

Aggregates collected fees across multiple tokens and converts them all to a single reference currency via the price oracle.

- **Auth:** None (read-only view)
- **Parameters:**
  - `tokens` — Vec of token contract addresses
  - `token_symbols` — Vec of token symbols (must match `tokens` length)
  - `reference_currency` — Target symbol for valuation (e.g., "USDC")
  - `token_decimals` — Vec of token decimal places (must match `tokens` length)
  - `ref_decimals` — Decimal places of reference currency
- **Returns:** Total collected fees in reference currency's smallest unit (i128)
- **Behavior:**
  - If no oracle is configured, returns 0
  - If a price is unavailable for a token/reference pair, that token is skipped (graceful degradation)
  - Conversions use `price_oracle.convert_with_decimals()` for decimal-aware math
  - Overflow is saturated at `i128::MAX`
- **Errors:** `InvalidAmount` if Vec lengths do not match

**Note:** This function currently requires the caller to pass the list of tokens. Once issue #36 (token registry) is implemented, a simpler parameterless `get_total_collected_value(reference_currency)` will iterate all whitelisted tokens automatically.

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
| `propose_upgrade(admin, wasm_hash)` | Admin\* | Propose contract upgrade |
| `execute_upgrade(admin)` | Admin | Apply upgrade after timelock |
| `propose_recipient(admin, recipient)` | Admin | Propose an allowed withdrawal destination |
| `execute_recipient(admin, recipient)` | Admin | Add recipient to allowlist after timelock |
| `is_recipient_allowed(recipient)` | None | Whether recipient is allowlisted |
| `set_reserve_allocation_bps(admin, bps)` | Admin | Set portion of new fees routed to loss reserve |
| `set_reserve_caller(admin, caller, authorized)` | Admin | Authorize a reserve disbursement caller |
| `disburse_from_reserve(caller, token, amount, recipient)` | Authorized caller | Draw down loss reserve |
| `get_reserve_balance(token)` / `get_reserve_allocation_bps()` / `is_reserve_caller(caller)` | None | Reserve views |
| `set_access_control(admin, access_control)` | Admin | Link an `access_control` multisig |
| `get_access_control()` | None | Current linked `access_control` address |
| `propose_treasury_action(proposer, action)` / `approve_treasury_action(approver, id)` / `execute_treasury_action(executor, id)` | Signer\* | Multisig-quorum flow for `withdraw`/`emergency_withdraw`/`set_fee_bps`/`propose_upgrade` |
| `get_treasury_proposal(id)` | None | Read a treasury proposal |

\* `withdraw`, `emergency_withdraw`, `set_fee_bps`, and `propose_upgrade` are Admin-only *directly*
only while no multisig with `threshold > 1` is linked via `set_access_control` — otherwise they
must go through the `propose_treasury_action` → `execute_treasury_action` flow instead.

---

## Storage Layout

| Key | Tier | Type | Description |
|-----|------|------|-------------|
| `Admin` | persistent | `Address` | Admin address |
| `FeeBps` | persistent | `u32` | Protocol fee rate |
| `PriceOracle` | persistent | `Address` | Price oracle contract (optional) |
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
4. Withdrawals only succeed if the live token balance, minus any reserve balance, covers the requested amount.
5. The `Collected` ledger is informational only — it never gates withdrawals.
6. `withdraw`/`emergency_withdraw` recipients must always be on the matured allowlist.
7. `ReserveBalance(token)` never exceeds the live token balance, and is never reduced by `withdraw`/`emergency_withdraw`.
8. When an `access_control` multisig with `threshold > 1` is linked, `withdraw`, `emergency_withdraw`, `set_fee_bps`, and `propose_upgrade` are unreachable except via an executed, quorum-approved `TreasuryProposal`.
