# Invoice NFT Contract

## Overview

The `invoice_nft` contract is the source of truth for every invoice in the Kora protocol. It mints invoice NFTs, owns the invoice lifecycle state machine, and is the sole authority that may advance or block status transitions.

## Status State Machine

```
Created → Listed → Funded → Repaid
                          ↘ Defaulted
```

| Transition   | Function      | Caller           |
|--------------|---------------|------------------|
| → Listed     | `set_listed`  | Marketplace      |
| → Funded     | `set_funded`  | Financing Pool   |
| → Repaid     | `set_repaid`  | Financing Pool   |
| → Defaulted  | `set_defaulted` | Admin          |

## Freeze Mechanism

### Design

Freeze enforcement is **owned internally by `invoice_nft`**, not delegated to callers. Every status-mutating function (`set_listed`, `set_funded`, `set_repaid`) calls the private `require_not_frozen` guard before executing. This provides defense-in-depth: no caller — current or future — can advance a frozen invoice's state by forgetting an external pre-check.

This is intentional and important. Earlier designs relied on external callers (e.g., `marketplace.fund_invoice`) to call `is_invoice_frozen` themselves before invoking invoice transitions. That approach is fragile: a single missed call site anywhere in the protocol silently defeats the freeze. The current design closes that class of bypass entirely.

### Admin Operations

| Function           | Who can call | Effect                                      |
|--------------------|--------------|---------------------------------------------|
| `freeze_invoice`   | Admin only   | Blocks all status transitions on the invoice |
| `unfreeze_invoice` | Admin only   | Removes the freeze; transitions resume       |
| `is_invoice_frozen`| Anyone       | Returns `true` if the invoice is frozen      |

### Error

A frozen invoice returns `KoraError::InvoiceFrozen (17)` on any attempted transition.

### Use Cases

- KYC / AML dispute on the SME or debtor
- Regulatory hold pending investigation
- Emergency administrative block

### Storage

Freeze state is stored as a `persistent` boolean under `DataKey::FrozenInvoice(invoice_id)`. The key is removed (not set to false) on unfreeze to reclaim storage.

## Error Codes

| Code | Variant                | Meaning                                  |
|------|------------------------|------------------------------------------|
| 10   | `InvoiceNotFound`      | No invoice exists for the given ID       |
| 11   | `InvoiceAlreadyExists` | Duplicate invoice ID in marketplace      |
| 12   | `InvalidInvoiceStatus` | Transition not allowed from current state |
| 13   | `InvoiceExpired`       | Invoice past due date                    |
| 14   | `InvalidAmount`        | Zero or negative amount                  |
| 15   | `InvalidDueDate`       | Due date not in the future               |
| 16   | `InvalidRiskScore`     | Risk score out of 0–100 range            |
| 17   | `InvoiceFrozen`        | Invoice is administratively frozen       |
