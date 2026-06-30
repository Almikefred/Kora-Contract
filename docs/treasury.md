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
4. **Acquire reentrancy guard**
5. Read live balance
6. If balance > 0: transfer full balance to recipient and emit `EmergencyWithdrawn`
7. If balance = 0: silent no-op (not an error)

Note: `emergency_withdraw` does **not** enforce the rolling rate-limit — it is intentionally unrestricted for emergency use. The reentrancy guard still applies.

---

## Reentrancy Protection

Both `withdraw` and `emergency_withdraw` acquire a RAII `ReentrancyGuard` before touching funds. The guard is implemented in `kora_shared::reentrancy`:

- Sets a `GuardKey::Lock` flag in instance storage on acquire
- Clears it in the `Drop` implementation, guaranteeing release even on early returns or panics
- Any re-entrant call into a guarded function returns `KoraError::Reentrancy` (discriminant 98)

The guard is acquired **after** all authorization and validation checks, so failed checks never leave the lock set.

---

## Rolling Withdrawal Rate-Limit

To cap the blast radius of a compromised admin key, withdrawals are subject to a configurable 24-hour rolling cap.

| Storage key | Type | Default | Meaning |
|-------------|------|---------|---------|
| `WithdrawalCap` | `i128` | `0` | Max withdrawable per 24 h epoch. `0` = uncapped |
| `EpochStart` | `u64` | init time | Timestamp of the current epoch start |
| `EpochWithdrawn` | `i128` | `0` | Amount withdrawn so far in the current epoch |

**Epoch reset:** if `now − EpochStart ≥ 86 400 s`, the epoch counters reset automatically at the next withdrawal.

**Changing the cap** uses a two-step timelock:

```
propose_withdrawal_cap(admin, new_cap)   // stores (new_cap, timestamp)
// wait ≥ UPGRADE_TIMELOCK_DELAY seconds
execute_withdrawal_cap(admin)            // applies new_cap
```

Executing before the timelock elapses returns `WithdrawalCapTimelockNotElapsed`. Executing without a pending proposal returns `NoCapChangeProposed`.

---

## Contract Upgrade

`propose_upgrade(admin, new_wasm_hash)` + `execute_upgrade(admin)` follow the same two-step timelock pattern. The upgrade is applied via `env.deployer().update_current_contract_wasm()` only after `UPGRADE_TIMELOCK_DELAY` has elapsed.

---

## Public API

| Function | Auth | Description |
|----------|------|-------------|
| `initialize(admin, fee_bps)` | None (one-time) | Set admin and fee rate |
| `set_fee_bps(admin, fee_bps)` | Admin | Update protocol fee |
| `whitelist_token(admin, token)` | Admin | Allow token for fee operations |
| `collect_fee(token, amount)` | None | Record incoming fee (called by marketplace) |
| `withdraw(admin, token, recipient, amount)` | Admin | Withdraw fees with rate-limit |
| `emergency_withdraw(admin, token, recipient)` | Admin | Drain full balance |
| `propose_withdrawal_cap(admin, new_cap)` | Admin | Propose new 24 h cap |
| `execute_withdrawal_cap(admin)` | Admin | Apply cap after timelock |
| `get_fee_bps()` | None | Read current fee rate |
| `get_balance(token)` | None | Live token balance |
| `get_collected(token)` | None | Informational ledger total |
| `get_withdrawal_cap()` | None | Current 24 h cap (0 = uncapped) |
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
| `WithdrawalCap` | instance | `i128` | 24 h withdrawal cap |
| `WithdrawalCapProposal` | instance | `(i128, u64)` | Pending cap change + timestamp |
| `EpochStart` | instance | `u64` | Current epoch start timestamp |
| `EpochWithdrawn` | instance | `i128` | Amount withdrawn in current epoch |

Persistent entries are TTL-bumped to ~31 days (`535 680` ledgers) on every write. Instance storage is tied to the contract instance and does not expire independently.

---

## Security Analysis

### Threat: stolen admin key

**Mitigations in place:**
- Rolling 24 h withdrawal cap limits the maximum extractable amount per epoch
- Cap changes require a timelock — an attacker cannot immediately raise the cap
- Contract upgrades require a timelock — an attacker cannot swap in malicious code immediately

**Residual risk:** with cap disabled (`WithdrawalCap = 0`), a compromised key can drain all funds in one transaction. The cap should always be set in production.

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
