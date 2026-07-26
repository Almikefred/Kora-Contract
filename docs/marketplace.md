# Marketplace Contract

## Overview

The Marketplace contract manages the listing lifecycle and investor funding flow for invoice-backed securities. It orchestrates the flow of funds from investors through the protocol: investors contribute capital, fees are deducted to the treasury, and net funds are held in the financing pool until the SME fulfills the invoice.

## Role in Kora Protocol

The Marketplace acts as the intermediary between SMEs (Small/Medium Enterprises) seeking financing and investors providing capital. It:

1. **Manages Listings** — SMEs create listings for specific invoices, specifying asking price and face value
2. **Collects Investor Funding** — Investors fund listings in shares, with fees automatically deducted
3. **Orchestrates Transitions** — Notifies Invoice NFT contract when status changes (Created → Listed → Funded)
4. **Releases Funds** — Triggers the Financing Pool to move funds to the SME when fully funded

## Public API Surface

### initialization

```
initialize(
  env: Env,
  admin: Address,
  invoice_nft: Address,
  financing_pool: Address,
  treasury: Address,
  fee_bps: u32
) -> Result<(), KoraError>
```

One-time initialization. Sets up the marketplace with pointers to other contracts and the protocol fee rate.

**Parameters:**
- `admin` — Protocol admin address (can pause, whitelist tokens, set fees)
- `invoice_nft` — Address of the Invoice NFT contract (for status transitions)
- `financing_pool` — Address of the Financing Pool (holds investor funds)
- `treasury` — Address of the Treasury (accumulates fees)
- `fee_bps` — Fee rate in basis points (0–10,000; e.g., 50 = 0.5%)

**Errors:**
- `AlreadyInitialized` — contract already initialized
- `InvalidAmount` — fee_bps > 10,000

### list_invoice

```
list_invoice(
  env: Env,
  seller: Address,
  invoice_id: u64,
  asking_price: i128,
  face_value: i128,
  token: Address,
  funding_deadline: u64
) -> Result<(), KoraError>
```

SME lists an invoice NFT for financing. Requires `seller` authentication. The asking price must be less than face value by at least the configured minimum discount (a meaningful discount must exist for investor yield).

**Parameters:**
- `seller` — SME address (must authenticate)
- `invoice_id` — ID of the invoice (from invoice_nft contract)
- `asking_price` — Target funding amount in tokens
- `face_value` — Nominal value of the underlying invoice
- `token` — Whitelisted stablecoin address
- `funding_deadline` — Unix timestamp; must be in the future
- `referrer` — Optional referrer address credited a share of the collected fee

**State Changes:**
- Persists a Listing struct with status `active` and `funded_amount = 0`
- Calls `invoice_nft.set_listed()` to transition invoice status

**Errors:**
- `InvalidAmount` — asking_price or face_value <= 0, asking_price >= face_value, or the discount (face_value - asking_price) is below the minimum discount requirement
- `InvalidDueDate` — funding_deadline in the past
- `TokenNotWhitelisted` — token not whitelisted by admin
- `InvoiceAlreadyExists` — listing already exists for this invoice_id

**Minimum Discount:**

To keep listings economically meaningful for investors (and to prevent fee-arbitrage or spam listings priced a stroop below face value), `list_invoice` enforces a minimum discount, expressed in basis points of `face_value`:

```
min_discount = face_value × min_discount_bps / 10_000
required: face_value - asking_price >= min_discount
```

- Defaults to `10` bps (0.1%) if never configured.
- Configurable by the admin via `set_min_discount_bps(admin, min_discount_bps)` (0–10,000 bps; validated with the same range as `fee_bps`).
- Read the current value with `get_min_discount_bps()`.

### fund_invoice

```
fund_invoice(
  env: Env,
  investor: Address,
  invoice_id: u64,
  amount: i128
) -> Result<(), KoraError>
```

Investor funds a share of an invoice. Marketplace fee is deducted and sent to treasury; net amount is transferred to the financing pool. When the listing reaches or exceeds asking_price, it is closed and the pool releases funds to the SME.

**Fee Model:**
```
gross_amount (from investor)
├── fee = gross_amount × fee_bps / 10_000  →  treasury
└── net = gross_amount - fee                →  financing_pool
```

**Parameters:**
- `investor` — Investor address (must authenticate)
- `invoice_id` — Invoice being funded
- `amount` — Gross contribution (fee calculated on this)

**State Changes:**
- Increments listing `funded_amount` by `amount`
- Transfers `fee` to treasury
- Transfers `net` to financing pool
- If fully funded (funded_amount >= asking_price):
  - Sets listing `is_active = false`
  - Calls `financing_pool.release_funds()` to move funds to SME
  - Calls `invoice_nft.set_funded()` to transition invoice status

**Errors:**
- `ListingNotFound` — no listing for this invoice_id
- `ListingAlreadyCancelled` — listing is inactive
- `FundingDeadlinePassed` — current time > funding_deadline
- `InvalidAmount` — amount <= 0
- `ExceedsFundingTarget` — amount would exceed asking_price
- `ArithmeticOverflow` — fee or net calculation overflowed

### cancel_listing

```
cancel_listing(
  env: Env,
  caller: Address,
  invoice_id: u64
) -> Result<(), KoraError>
```

Cancel a listing before it is fully funded. Caller must be the seller or the admin.

**Parameters:**
- `caller` — Address attempting to cancel (must be seller or admin)
- `invoice_id` — Listing to cancel

**State Changes:**
- Sets listing `is_active = false`

**Errors:**
- `ListingNotFound` — no listing for this invoice_id
- `ListingAlreadyCancelled` — listing already inactive
- `Unauthorized` — caller is neither seller nor admin

### whitelist_token

```
whitelist_token(
  env: Env,
  admin: Address,
  token: Address
) -> Result<(), KoraError>
```

Whitelist a stablecoin token for use in listings. Admin only. Multiple tokens can be whitelisted; all new listings must use a whitelisted token.

**Parameters:**
- `admin` — Protocol admin (must authenticate and be authorized)
- `token` — Token address to whitelist

**Errors:**
- `NotAdmin` — caller is not the admin

### get_listing

```
get_listing(
  env: Env,
  invoice_id: u64
) -> Result<Listing, KoraError>
```

Get a listing by invoice_id. Returns the full Listing struct.

**Returns:**
- `Listing` — containing invoice_id, seller, asking_price, face_value, token, funded_amount, funding_deadline, is_active

**Errors:**
- `ListingNotFound` — no listing for this invoice_id

## Typical Usage Flow

### 1. Listing (SME initiates)

```
list_invoice(
  seller=sme_address,
  invoice_id=1,
  asking_price=9_500_000_000,     // 9,500 USDC (offer a discount)
  face_value=10_000_000_000,       // 10,000 USDC (invoice amount)
  token=usdc_address,
  funding_deadline=timestamp_30_days_from_now
)
```

Result: Listing is created, invoice status becomes `Listed`.

### 2. Funding (Investor(s) contribute)

```
fund_invoice(
  investor=investor_address,
  invoice_id=1,
  amount=4_000_000_000     // first investor contributes 4,000 USDC
)
// marketplace deducts fee: 4_000_000_000 × 50 / 10_000 = 20_000_000 USDC
// net to pool: 3_980_000_000 USDC
// fee to treasury: 20_000_000 USDC
```

Multiple investors can fund in tranches.

### 3. Full Funding & Release (Automatic when target reached)

```
// Second investor completes the funding:
fund_invoice(
  investor=investor_address_2,
  invoice_id=1,
  amount=5_500_000_000     // second investor contributes 5,500 USDC
)
// Total funded: 9,500,000,000 USDC (matches asking_price)
// Marketplace automatically:
//   1. Deducts fee (27,500,000 USDC) to treasury
//   2. Transfers net (5,472,500,000 USDC) to pool
//   3. Calls financing_pool.release_funds()
//   4. SME receives funds net of marketplace fees
//   5. Invoice status transitions to Funded
```

### 4. Settlement (SME repays or defaults)

See `financing_pool` contract for repayment and yield distribution.

## Security Considerations

### Input Validation

- **Amounts:** All contributions must be > 0. Asking price must be < face value (ensures discount/yield).
- **Timestamps:** Funding deadline must be in the future.
- **Tokens:** Only whitelisted tokens are accepted. Admin controls which tokens are used.
- **Listing State:** Cannot fund a cancelled listing. Cannot exceed asking price.

### Fee Calculation

Fees use checked arithmetic (`bps_of`) to prevent overflow. Overflows return `ArithmeticOverflow` error.

### Cross-Contract Calls

Marketplace calls Invoice NFT and Financing Pool via authenticated calls. Each callee verifies the caller is the marketplace contract. No direct state mutation across contracts.

### Reentrancy

Token transfers happen after all state updates (checks-effects-interactions pattern). Financing Pool uses a reentrancy guard on withdrawal operations.

## Error Codes

| Error | Meaning |
|-------|---------|
| `InvalidAmount` | Amount <= 0 or price validation failed |
| `InvalidDueDate` | Deadline in the past |
| `TokenNotWhitelisted` | Token not whitelisted |
| `InvoiceAlreadyExists` | Listing already created for this invoice |
| `ListingNotFound` | No listing for given invoice_id |
| `ListingAlreadyCancelled` | Listing is inactive |
| `FundingDeadlinePassed` | Current time > deadline |
| `ExceedsFundingTarget` | Funding amount would exceed asking_price |
| `NotAdmin` | Caller is not the admin |
| `Unauthorized` | Caller not authorized for this operation |
| `ArithmeticOverflow` | Arithmetic operation overflowed |

## Storage Model

Listings are stored in persistent storage with listing ID as key. Each listing is a separate entry with its own TTL. Whitelisted tokens are stored as boolean flags.

## Admin Operations

- **Initialize:** Set up marketplace with pointers to other contracts
- **Whitelist Tokens:** Add tokens that SMEs and investors can use
- **Pause Protocol:** Via access_control contract (pauses state-mutating operations)
- **Set Fees:** Update the marketplace fee rate (future enhancement)
