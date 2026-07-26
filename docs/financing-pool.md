# Financing Pool Contract

The `financing_pool` contract is the custodian of investor funds within the Kora Protocol. It holds tokens contributed by investors, tracks each investor's proportional position, distributes repayments and yield, and handles defaults and late penalties.

---

## Overview

When an invoice is fully funded on the marketplace, the marketplace calls `release_funds` on the financing pool. From that point, the pool:

1. Creates a `Pool` record tied to the invoice, copying the face value from the NFT.
2. Tracks each investor's contributed amount and share in basis points (`share_bps`).
3. Accepts repayment from the SME via `repay`.
4. Applies a one-time late-penalty if repayment arrives after `due_date`.
5. Distributes principal + yield to all investors proportionally on full repayment.
6. Handles partial distribution in the event of a default via `mark_default`.

---

## Data Structures

### `Pool`

```rust
pub struct Pool {
    pub invoice_id: u64,
    pub token: Address,        // whitelisted stablecoin address
    pub total_funded: i128,    // total contributions received (stroops)
    pub face_value: i128,      // full repayment amount copied from NFT (stroops)
    pub repaid_amount: i128,   // cumulative amount repaid so far
    pub is_closed: bool,       // true once fully repaid or defaulted
    pub late_penalty_bps: u32, // one-time late penalty in basis points
    pub total_owed: i128,      // face_value + any applied penalty
    pub penalty_applied: bool, // true once the late penalty has been added
}
```

### `Position`

```rust
pub struct Position {
    pub investor: Address,
    pub invoice_id: u64,
    pub contributed: i128, // amount this investor contributed (stroops)
    pub share_bps: u32,    // proportional share in bps (10 000 = 100 %)
    pub yield_claimed: i128,
}
```

### `InstallmentSchedule` (optional)

```rust
pub struct InstallmentSchedule {
    pub installments: Vec<Installment>, // ordered list; sum == Pool.total_owed
    pub next_index: u32,                // index of the next unpaid installment
}

pub struct Installment {
    pub due_date: u64,  // Unix timestamp; late-penalty applies if missed
    pub amount: i128,   // amount due for this installment (stroops)
    pub paid: bool,
}
```

---

## Storage Layout

| Key | Tier | Type | Description |
|-----|------|------|-------------|
| `Admin` | instance | `Address` | Contract admin |
| `InvoiceNft` | instance | `Address` | Invoice NFT contract |
| `RiskRegistry` | instance | `Address` | Risk registry contract |
| `Treasury` | instance | `Address` | Treasury contract |
| `AccessControl` | instance | `Address` | Pause-check contract |
| `PriceOracle` | instance | `Address` | Price oracle for cross-currency conversion |
| `LatePenaltyBps` | instance | `u32` | Late repayment penalty in bps |
| `MaxPositionBps` | instance | `u32` | Per-investor concentration cap in bps |
| `ProtocolStats` | instance | `ProtocolStats` | Aggregate counters |
| `Pool(u64)` | persistent | `Pool` | Pool state keyed by invoice ID |
| `Positions(u64)` | persistent | `Map<Address, Position>` | Investor positions per invoice |
| `RepaymentLock(u64)` | persistent | `bool` | Reentrancy guard for `repay` |
| `InstallmentSchedule(u64)` | persistent | `InstallmentSchedule` | Optional repayment schedule |
| `EarlySettlement(u64)` | persistent | `EarlySettlementOffer` | Pending buyout offer |
| `SaleOffer(u64, Address)` | persistent | `PositionSaleOffer` | Secondary-market sale listing |
| `AggregateFunded(Address)` | instance | `i128` | Protocol-wide outstanding obligations per token |

---

## Core Arithmetic

### `bps_of(amount, bps)`

Plain basis-point fraction — used for the **late penalty**:

```
result = (amount × bps) / 10_000
```

Example: `bps_of(10_000_000_000, 200)` → `200_000_000` (2 % of 10 B stroops).

### `bps_of_normalized(amount, bps, token_decimals)`

Decimal-aware basis-point fraction — used for **yield payouts**. It first normalises the amount to Soroban's standard 7-decimal precision, computes the fraction, then denormalises back to the token's native precision. For USDC (6 decimals) this matters; for 7-decimal tokens it is identical to `bps_of`.

```
normalized  = amount × 10^(7 − token_decimals)   // scale up for 6-decimal tokens
result_norm = (normalized × bps) / 10_000
result      = result_norm / 10^(7 − token_decimals)  // scale back down
```

The net effect is that rounding always happens in the token's native precision, preventing systematic rounding bias in favour of one party.

### `share_bps` calculation

When `record_position` is called after each investor contribution:

```
share_bps = (contributed × 10_000) / total_pool
```

Invariant: for a fully-funded pool the sum of all `share_bps` values equals 10 000 (any integer rounding leaves a dust remainder that accumulates in the pool).

---

## Worked Example — Two Investors, On-Time Repayment

### Setup

| Parameter | Value |
|-----------|-------|
| Invoice face value | 10 000 USDC (= 10 000 000 000 stroops, 7 dec) |
| Asking price (marketplace) | 9 500 USDC (= 9 500 000 000 stroops) |
| Marketplace fee | 50 bps (0.5 %) |
| Late penalty | 200 bps (2 %) |
| Token decimals | 7 (Stellar-native USDC) |

### Step 1 — Investors fund the listing

Investor A contributes 5 700 USDC; Investor B contributes 3 800 USDC.  
Total funded = 9 500 USDC = `asking_price`. Listing closes.

Marketplace fee per investor (50 bps, via `bps_of_normalized`):

```
fee_A = bps_of_normalized(5_700_000_000, 50, 7)
      = (5_700_000_000 × 50) / 10_000
      = 28_500_000   (28.5 USDC)

fee_B = bps_of_normalized(3_800_000_000, 50, 7)
      = (3_800_000_000 × 50) / 10_000
      = 19_000_000   (19 USDC)
```

Net transferred to financing pool:

```
net_A = 5_700_000_000 − 28_500_000 = 5_671_500_000  (5 671.5 USDC)
net_B = 3_800_000_000 − 19_000_000 = 3_781_000_000  (3 781 USDC)
total_net = 9_452_500_000 stroops
```

### Step 2 — `release_funds` creates the Pool

```
Pool {
    face_value:      10_000_000_000,
    total_funded:    0,              // updated by record_position calls
    repaid_amount:   0,
    is_closed:       false,
    late_penalty_bps: 200,
    total_owed:      10_000_000_000,
    penalty_applied: false,
}
```

### Step 3 — `record_position` records investor shares

Marketplace admin calls `record_position` once per investor.  
`total_pool` passed in is the final `asking_price` = 9 500 000 000.

```
share_bps_A = (5_700_000_000 × 10_000) / 9_500_000_000
            = 57_000_000_000_000 / 9_500_000_000
            = 6 000  (60.00 %)

share_bps_B = (3_800_000_000 × 10_000) / 9_500_000_000
            = 38_000_000_000_000 / 9_500_000_000
            = 4 000  (40.00 %)

sum = 6 000 + 4 000 = 10 000  ✓
```

### Step 4 — SME repays on time

SME calls `repay(sme, invoice_id, token, 10_000_000_000)`.

- `env.ledger().timestamp() ≤ invoice.due_date` → no penalty.
- `repaid_amount = 10_000_000_000 ≥ total_owed = 10_000_000_000` → pool closes.

`distribute_yield` is called with `total_repaid = 10_000_000_000`.

```
payout_A = bps_of_normalized(10_000_000_000, 6_000, 7)
         = (10_000_000_000 × 6_000) / 10_000
         = 6_000_000_000  (6 000 USDC)

yield_A  = 6_000_000_000 − 5_671_500_000 = 328_500_000  (328.5 USDC)

payout_B = bps_of_normalized(10_000_000_000, 4_000, 7)
         = (10_000_000_000 × 4_000) / 10_000
         = 4_000_000_000  (4 000 USDC)

yield_B  = 4_000_000_000 − 3_781_000_000 = 219_000_000  (219 USDC)
```

**Summary:**

| | Contributed (net) | Received | Yield |
|--|--|--|--|
| Investor A | 5 671.5 USDC | 6 000 USDC | +328.5 USDC (+5.79 %) |
| Investor B | 3 781 USDC | 4 000 USDC | +219 USDC (+5.79 %) |
| SME paid | — | 10 000 USDC | — |

---

## Worked Example — Late Repayment with Penalty

Same setup as above. SME repays **after** `invoice.due_date`.

### Step 4b — `repay` detects late payment

```
env.ledger().timestamp() > invoice.due_date  →  apply penalty

penalty = bps_of(face_value, late_penalty_bps)
        = bps_of(10_000_000_000, 200)
        = (10_000_000_000 × 200) / 10_000
        = 200_000_000  (200 USDC)

total_owed = 10_000_000_000 + 200_000_000 = 10_200_000_000
penalty_applied = true
```

Event `late_penalty_applied(invoice_id, 200_000_000, 10_200_000_000)` is emitted.

SME must call `repay` with `amount = 10_200_000_000` (or the pool accepts any
cumulative amount ≥ `total_owed` across multiple partial calls).

### Yield distribution after late repayment

```
payout_A = bps_of_normalized(10_200_000_000, 6_000, 7)
         = (10_200_000_000 × 6_000) / 10_000
         = 6_120_000_000  (6 120 USDC)

yield_A  = 6_120_000_000 − 5_671_500_000 = 448_500_000  (448.5 USDC)

payout_B = bps_of_normalized(10_200_000_000, 4_000, 7)
         = (10_200_000_000 × 4_000) / 10_000
         = 4_080_000_000  (4 080 USDC)

yield_B  = 4_080_000_000 − 3_781_000_000 = 299_000_000  (299 USDC)
```

The 200 USDC penalty is distributed pro-rata to investors (not to the treasury).

---

## Worked Example — Three Investors, Partial Repayment (Default)

### Setup

| Parameter | Value |
|-----------|-------|
| Face value | 30 000 USDC |
| Investors | C (50 %), D (30 %), E (20 %) |
| SME partial repayment before default | 9 000 USDC |

```
share_bps_C = 5 000   (50 %)
share_bps_D = 3 000   (30 %)
share_bps_E = 2 000   (20 %)
```

Admin calls `mark_default` after the due date passes without full repayment.  
`pool.repaid_amount = 9 000 000 000` (SME paid 9 000 USDC in a prior `repay` call).

`distribute_yield` is called with `total_repaid = 9_000_000_000`:

```
payout_C = bps_of_normalized(9_000_000_000, 5_000, 7) = 4_500_000_000  (4 500 USDC)
payout_D = bps_of_normalized(9_000_000_000, 3_000, 7) = 2_700_000_000  (2 700 USDC)
payout_E = bps_of_normalized(9_000_000_000, 2_000, 7) = 1_800_000_000  (1 800 USDC)
total distributed = 9 000 USDC  ✓
```

Each investor recovers 30 % of their contributed principal (9 000 / 30 000).  
Yield is negative; `yield_claimed` is not updated on default (the contract
distributes whatever was recovered, no separate yield event is emitted for defaults).

---

## Worked Example — Installment Schedule

### Setup

| Parameter | Value |
|-----------|-------|
| Face value / `total_owed` | 12 000 USDC |
| Schedule | 3 installments of 4 000 USDC each |
| Installment due dates | T+30d, T+60d, T+90d |
| Investor F | 100 % share (share_bps = 10 000) |

Admin calls `set_installment_schedule` after `release_funds`.

### Installment 1 — on time

SME calls `repay(sme, invoice_id, token, 4_000_000_000)` before T+30d.

- `effective_amount == installment[0].amount` ✓
- `timestamp ≤ installment[0].due_date` → no penalty
- `installment[0].paid = true`, `next_index = 1`
- `pool.repaid_amount = 4_000_000_000`
- Pool not yet closed; no yield distribution yet.

### Installment 2 — late

SME calls `repay` after T+60d.

- `timestamp > installment[1].due_date` → penalty applied (one-time):

```
penalty = bps_of(12_000_000_000, 200) = 240_000_000  (240 USDC)
total_owed = 12_000_000_000 + 240_000_000 = 12_240_000_000
```

- `installment[1].paid = true`, `next_index = 2`
- `pool.repaid_amount = 8_000_000_000`

### Installment 3 — final (accepts ≥ expected)

The last installment's expected amount is still 4 000 USDC, but `total_owed` grew by
240 USDC.  For the final installment the contract accepts any `amount ≥ expected`, so
the SME pays the remaining balance:

```
remaining = total_owed − repaid_amount
          = 12_240_000_000 − 8_000_000_000
          = 4_240_000_000
```

SME calls `repay(sme, invoice_id, token, 4_240_000_000)`.

- `effective_amount (4 240 M) ≥ expected (4 000 M)` ✓ (final installment accepts ≥)
- `pool.repaid_amount = 12_240_000_000 ≥ total_owed = 12_240_000_000` → pool closes.

Yield distribution:

```
payout_F = bps_of_normalized(12_240_000_000, 10_000, 7)
         = 12_240_000_000  (100 % share — all funds go to F)
```

---

## Entry Points

### `initialize`

One-time setup. Stores all contract references and configuration.

```rust
pub fn initialize(
    env: Env,
    admin: Address,
    invoice_nft: Address,
    risk_registry: Address,
    treasury: Address,
    access_control: Address,
    late_penalty_bps: u32,   // 0–10 000
    price_oracle: Address,
    max_position_bps: u32,   // 1–10 000
) -> Result<(), FinancingPoolError>
```

**Errors:** `AlreadyInitialized`, `InvalidFeeRate` (late_penalty_bps > 10 000 or
max_position_bps is 0 / > 10 000), `InvalidAddress` (any address is the contract itself).

---

### `release_funds`

Called by the marketplace when an invoice reaches full funding.

```rust
pub fn release_funds(
    env: Env,
    marketplace: Address,
    invoice_id: u64,
    token: Address,
) -> Result<(), FinancingPoolError>
```

Creates a `Pool` record, emits `pool_opened`, and calls `invoice_nft.set_funded`.

**Auth:** `marketplace.require_auth()`

---

### `record_position`

Records (or overwrites) an investor's position. Called by the admin after each
`fund_invoice` contribution.

```rust
pub fn record_position(
    env: Env,
    caller: Address,   // must be admin
    invoice_id: u64,
    investor: Address,
    contributed: i128,
    total_pool: i128,
) -> Result<(), FinancingPoolError>
```

Computes `share_bps = (contributed × 10_000) / total_pool`.  
Enforces the per-investor concentration cap (`max_position_bps`).

**Errors:** `NotAdmin`, `ProtocolPaused`, `InvalidAmount`, `ExceedsFundingTarget`,
`ArithmeticOverflow`, `PoolNotFound`.

---

### `repay`

SME repays the invoice. Follows Checks-Effects-Interactions.

```rust
pub fn repay(
    env: Env,
    payer: Address,
    invoice_id: u64,
    token: Address,
    amount: i128,
) -> Result<(), FinancingPoolError>
```

1. Validates amount, checks invoice freeze and reentrancy lock.
2. Applies late penalty if `timestamp > due_date` (or installment `due_date`) and
   `!pool.penalty_applied`.
3. If an installment schedule is present, validates the `amount` against the current
   installment (exact match; final installment accepts ≥ expected).
4. Updates `pool.repaid_amount`; closes pool if `≥ total_owed`.
5. Transfers tokens into the contract (`token.transfer`).
6. If closed, calls `distribute_yield` then `invoice_nft.set_repaid`.

**Auth:** `payer.require_auth()`  
**Reentrancy:** per-invoice `RepaymentLock` in persistent storage.

---

### `mark_default`

Admin-only. Marks a pool as defaulted and distributes any partial recovery pro-rata.

```rust
pub fn mark_default(
    env: Env,
    admin: Address,
    invoice_id: u64,
    token: Address,
) -> Result<(), FinancingPoolError>
```

**Auth:** `admin.require_auth()` + admin check.  
**Errors:** `NotAdmin`, `ProtocolPaused`, `Unauthorized` (lock held),
`PoolNotFound`, `PoolAlreadyClosed`.

---

### `set_installment_schedule`

Attach a repayment schedule to an open pool. Admin only. Must be called before any
repayment. The sum of all installment amounts must equal `pool.total_owed`.

---

### `propose_early_settlement` / `accept_early_settlement`

Allow the SME to offer a discounted buyout to investors.  
`amount` must satisfy `total_funded ≤ amount < total_owed`.  
The amount is escrowed immediately; once investors holding 100 % of `share_bps`
accept, the pool closes and funds are distributed pro-rata.

---

### `list_position_for_sale` / `buy_position`

Secondary market for investor positions. A position holder can list at any price;
any buyer can purchase, inheriting the original `share_bps` and `contributed` values.

---

## Security Properties

- **Checks-Effects-Interactions:** In `repay`, all state mutations occur before any
  token transfer.
- **Reentrancy guard:** `RepaymentLock(invoice_id)` is set at the start of `repay`
  and removed at the end. Concurrent re-entry returns `Unauthorized`.
- **Safe arithmetic:** All financial math uses `checked_mul`, `checked_div`,
  `checked_add`, `checked_sub`. Any overflow returns `ArithmeticOverflow`.
- **Overflow-safe ceiling:** `MAX_AMOUNT = i128::MAX / 2` prevents intermediate
  overflow when multiplying amounts by bps values (up to 10 000).
- **Concentration cap:** `max_position_bps` limits any single investor to a
  configurable share of a pool, preventing monopolistic funding.
- **One-time penalty:** `pool.penalty_applied` ensures the late penalty is added
  exactly once regardless of the number of partial repayment calls.
- **Freeze support:** `invoice_nft.is_invoice_frozen` is checked before accepting
  repayment, enabling targeted per-invoice freeze without a protocol-wide pause.

---

## Error Reference

| Error | Code | Meaning |
|-------|------|---------|
| `AlreadyInitialized` | 1 | `initialize` called twice |
| `ArithmeticOverflow` | 2 | Checked arithmetic returned `None` |
| `ExceedsFundingTarget` | 3 | Investor share exceeds `max_position_bps` |
| `InvalidAddress` | 4 | Address is the contract itself |
| `InvalidAmount` | 5 | Amount out of valid range |
| `InvalidDueDate` | 6 | Due date validation failed |
| `InvalidFeeRate` | 7 | `late_penalty_bps > 10 000` or `max_position_bps` out of range |
| `InvoiceFrozen` | 8 | Invoice is individually frozen |
| `NoUpgradeProposed` | 9 | No pending upgrade proposal |
| `NotAdmin` | 10 | Caller is not the admin |
| `NotInitialized` | 11 | Storage keys not set |
| `PoolAlreadyClosed` | 12 | Pool is already repaid or defaulted |
| `PoolNotFound` | 13 | No pool for this invoice ID |
| `PositionNotFound` | 14 | Investor does not hold a position |
| `ProtocolPaused` | 15 | Protocol is paused via AccessControl |
| `RepaymentAlreadyMade` | 16 | Pool was closed before this `repay` call |
| `SaleAlreadyListed` | 17 | Position already listed for secondary sale |
| `SaleNotFound` | 18 | No active sale listing found |
| `Unauthorized` | 19 | Reentrancy lock held or caller mismatch |
| `UpgradeTimelockNotElapsed` | 20 | 24-hour upgrade timelock not yet passed |
