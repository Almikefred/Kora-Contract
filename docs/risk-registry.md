# Risk Registry

The `risk_registry` contract is the trust anchor for the Kora protocol. It manages verifier
on-boarding, SME creditworthiness scoring, debtor scoring, and the credit-limit enforcement
that prevents over-exposure. Every invoice minted by `invoice_nft` and every funding decision
in `marketplace` ultimately depends on the data held here.

---

## Overview

```
Admin
 │── add_verifier(verifier, stake) ──► Verifier registered (stake escrowed)
 │
Verifier
 │── register_sme(sme, score, compliance_attested) ──► SmeProfile created
 │── update_sme_score(sme, new_score)               ──► score + risk_tier updated
 │── set_credit_limit(sme, limit)                   ──► credit ceiling set
 │── set_debtor_score(debtor_hash, score)            ──► debtor scored
 │
invoice_nft
 │── increment_invoice_count(sme)  ──► total_invoices++
 │
Admin
 └── record_default(sme)           ──► defaults++, verifier stake slashed
```

---

## Verifier Trust Model

### Registration

A verifier is a trusted, off-chain KYC/AML provider or credit bureau. Before a verifier
can score any SME they must be registered by the admin with a staking deposit:

```
add_verifier(admin, verifier, stake_amount)
```

- `stake_amount` must be ≥ `minimum_stake` (set at initialization).
- The stake is transferred from `verifier` to the registry contract immediately.
- Initial `reputation` is set to **100**.

### Reputation & Slashing

Verifier reputation is a signal of historical accuracy. When an SME that a verifier
registered defaults on an invoice, the admin calls `record_default(admin, sme)`:

1. `SmeProfile.defaults` is incremented.
2. A fraction of the verifier's remaining stake is slashed: `slash = stake * slash_percentage_bps / 10_000`.
3. The slashed amount is burned (transferred to the zero address / left in contract).
4. The verifier's `reputation` score is decremented by 1 per default (floor: 0).

Verifiers with a depleted stake or low reputation are a signal to the admin to
call `remove_verifier`, which returns any remaining stake and purges the verifier records.

### Removal

```
remove_verifier(admin, verifier)
```

Removes all three verifier storage entries (`Verifier`, `VerifierStake`,
`VerifierReputation`) and returns the remaining (unslashed) stake to the verifier address.

---

## SME Registration & Scoring Lifecycle

### Registration

Only a registered verifier can introduce an SME to the protocol:

```
register_sme(verifier, sme, risk_score, compliance_attested)
```

This creates an `SmeProfile` entry:

| Field | Initial value |
|---|---|
| `address` | `sme` |
| `verified` | `true` |
| `verifier` | caller |
| `risk_score` | 0–100 |
| `total_invoices` | 0 |
| `defaults` | 0 |
| `registered_at` | current ledger timestamp |
| `compliance_attested` | caller's attestation flag |

Re-registration of an existing SME is rejected (`KoraError::AlreadyInitialized`) to
prevent silent reset of default and invoice counters.

### Score Updates

A verifier may update the risk score at any time:

```
update_sme_score(verifier, sme, new_score)
```

The `risk_score` and derived `risk_tier` (see below) in the `SmeProfile` are updated
atomically. This affects future invoice minting only — already-minted invoices retain
the score they were issued with.

### Credit Limit

A verifier sets a maximum outstanding face-value exposure for an SME:

```
set_credit_limit(verifier, sme, credit_limit)
```

- `credit_limit = 0` means **uncapped**.
- When `invoice_nft::mint_invoice` is called, it queries
  `invoice_nft::get_outstanding_exposure(sme)` and rejects the mint if
  `outstanding + new_amount > credit_limit`.

---

## Risk Tier Thresholds

The `RiskTier` is derived from the numeric `risk_score` (0–100) via
`RiskTier::from_score`:

| Tier | Score Range | Risk Profile |
|------|-------------|--------------|
| AAA  | 0–20        | Lowest risk. Blue-chip debtors, strong SME repayment history. |
| AA   | 21–40       | Low risk. Established SME, reliable debtor. |
| A    | 41–60       | Moderate risk. Standard trade finance profile. |
| B    | 61–80       | Elevated risk. Newer SME or less-known debtor. |
| C    | 81–100      | High risk. Requires higher yield to attract investors. |

The tier is stored directly on the `Invoice` struct at mint time. Marketplace
interfaces may surface tier information to investors to aid funding decisions.

---

## Debtor Scoring

Debtors are the counterparties who owe payment on the underlying invoices. To preserve
privacy, debtor PII is never stored on-chain — only a **SHA-256 hash** of the debtor
identity is used as the key.

```
set_debtor_score(verifier, debtor_hash, score)
```

- `debtor_hash` must be exactly 32 bytes (the raw SHA-256 digest).
- `score` is 0–100, following the same `RiskTier` mapping as SME scores.
- Only registered verifiers may set debtor scores.

Query:

```
get_debtor_score(debtor_hash) → Result<u32, KoraError::DebtorNotRegistered>
```

Debtor scores are currently informational — they are not enforced by any contract
logic in v1 but are available for off-chain risk dashboards and future marketplace
tier-based fee differentiation.

---

## Invoice Count Tracking

`invoice_nft` calls `increment_invoice_count(caller, sme)` automatically each time a
new invoice is minted. Only the `invoice_nft` address registered at initialization may
call this function.

This increments `SmeProfile.total_invoices`, providing an on-chain record of SME
activity volume for risk analysis.

---

## Read-Only View Functions

| Function | Returns |
|---|---|
| `get_sme_profile(sme)` | Full `SmeProfile` struct, or `KoraError::SMENotRegistered` |
| `is_verified_sme(sme)` | `true` if the SME has a profile and `verified == true` |
| `is_compliance_attested(sme)` | `true` if the verifier attested KYC/AML compliance |
| `get_verifier_stake(verifier)` | Remaining stake in token units (0 if not registered) |
| `get_verifier_reputation(verifier)` | Reputation score 0–100 (0 if not registered) |
| `is_verifier(verifier)` | `true` if the address is a registered verifier |
| `get_debtor_score(debtor_hash)` | Debtor score, or `KoraError::DebtorNotRegistered` |
| `get_admin()` | Current admin address |

All read functions are authorization-free and safe to call from any context.

---

## Storage & TTL

All SME profiles and verifier entries use **persistent** storage with a ~30-day TTL
(518 400 ledgers). The operator or a keeper bot must periodically call `extend_ttl` on
active profiles to prevent expiry. Expired profiles are treated as unregistered by the
contract — `is_verified_sme` returns `false` for expired keys.

---

## Security Notes

- Verifier registration requires a token stake deposit that is slashed on SME defaults,
  creating skin-in-the-game incentives for honest scoring.
- Only the admin may add or remove verifiers; only verifiers may register or score SMEs.
- `increment_invoice_count` is callable only by the `invoice_nft` contract address
  set at initialization — it cannot be spoofed by an arbitrary caller.
- Debtor PII never appears on-chain; only SHA-256 hashes are stored.
- Reentrancy protection (`ReentrancyGuard`) is applied on `update_sme_score` which
  performs an inter-contract read.

---

## Related Documents

- [ARCHITECTURE.md](ARCHITECTURE.md) — full contract dependency graph
- [CONTRACTS.md](CONTRACTS.md) — per-contract reference table
- [SECURITY.md](SECURITY.md) — protocol-wide security model
- [docs/invoice-nft.md](invoice-nft.md) — credit-limit enforcement at mint time
