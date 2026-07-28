# Schema Migrations

This document tracks breaking changes to persistent storage layouts and required data migrations.

## ParameterProposal schema change (PR #XXX, Issue #490)

### Change
Added `expires_at: u64` field to `ParameterProposal` struct in `contracts/shared/src/types.rs`.

### Migration Notes
- **Already-deployed instances:** Existing ParameterProposal entries in storage lack the `expires_at` field.
- **Safe handling:** The field default (missing = 0) makes old proposals immediately expired, preventing execution.
- **Best practice:** After contract upgrade, re-propose any critical pending parameter changes with fresh TTL.
- **No data loss:** Old entries remain readable via `get_parameter_proposal` but cannot be voted on or executed after expiry.

### Timeline
- ParameterProposal TTL: ~7 days (PROPOSAL_TTL_LEDGERS = 120_960 ledgers at ~5s/ledger)
- Proposals expire after creation time + TTL
- Expired proposals cannot be voted on or executed

## Multisig Direct-Call Blocking (PR #XXX, Issue #487)

### Change
Added `DirectCallProhibited` error. Once a multisig is configured via `configure_multisig`, direct admin calls to:
- `pause()`
- `unpause()`
- `grant_role()`
- `revoke_role()`
- `transfer_admin()`

...are blocked and must route through `propose_action → approve_action → execute_action`.

### Migration Notes
- **No storage change:** Existing state is unaffected.
- **Behavior change:** Direct calls fail with `DirectCallProhibited` after multisig is active.
- **Before multisig:** All direct admin calls work normally.
- **After multisig:** Must use propose/approve/execute flow (intentional security hardening).
