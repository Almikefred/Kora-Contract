# Kora Protocol — Audit Log

This document tracks audit findings, fixes, and their resolution across all protocol releases.

---

## Finding B27: Event Deduplication in SME Profile Tracking

**Status:** ✅ Fixed in [Unreleased]

**Severity:** Low

**Description:**

The shared events module contained a duplicate event `sme_invoice_counted` that was redundant with `sme_invoice_count_incremented`. This duplication created confusion in off-chain analytics and event indexing.

**Location:**

- `contracts/shared/src/events.rs` — event definitions

**Fix Applied:**

Removed `sme_invoice_counted` event. All SME invoice count tracking now uses `sme_invoice_count_incremented`.

**Verification:**

1. Grep the codebase for `sme_invoice_counted` — should return no results
2. Verify all tests pass: `cargo test --all`
3. Review event emission sites in risk_registry and financing_pool contracts to confirm only the incremented event is used

**Cross-References:**

- [CHANGELOG.md](CHANGELOG.md) → [Unreleased] → Fixed
- [CONTRIBUTING.md](CONTRIBUTING.md) → Changelog Process section

---

## Finding B16: Marketplace Token Whitelist Enforcement

**Status:** ✅ Mitigated by design

**Severity:** Medium

**Description:**

Only whitelisted tokens can be used for invoice funding. Protects against accidental or malicious use of untrusted tokens.

**Location:**

- `contracts/marketplace/src/lib.rs` — `whitelist_token()`, `fund_invoice()` validation

**Mitigation:**

The marketplace contract enforces a token whitelist:

```rust
if !env.storage().persistent().has(&DataKey::WhitelistedToken(token.clone())) {
    return Err(KoraError::TokenNotWhitelisted);
}
```

Whitelist is admin-controlled. Tokens can only be added/removed by the admin address.

**Verification:**

- Unit test: `test_fund_invoice_with_unlisted_token` confirms rejection
- Integration test: `test_marketplace_lifecycle` confirms whitelisted tokens work

---

## Finding B2: Multisig Admin Requirements

**Status:** ⏳ Planned for v2

**Severity:** High

**Description:**

Single admin key control creates operational and key-management risk. Multisig (M-of-N threshold) is recommended for production deployments.

**Location:**

- `contracts/access_control/src/lib.rs` — `transfer_admin()` single-key design

**Mitigation (Current):**

- Admin key is protected and operated by the Kora Foundation
- Pause mechanism allows immediate emergency freeze of protocol
- All admin actions are logged and auditable via event emission

**Planned Fix (v2):**

- Replace single `admin: Address` with `admins: Vec<Address>` and `threshold: u32`
- Implement `propose_admin_action()` and `approve_admin_action()` with timelock
- Require M-of-N signatures for sensitive operations (pause, fee changes, token whitelist)

**Target Release:** v2.0.0 (Q3 2026)

---

## Audit Finding Template

Use this template when documenting new findings:

```markdown
## Finding BXX: [Short Title]

**Status:** [✅ Fixed | ⏳ Planned | 🚨 Open]

**Severity:** [Critical | High | Medium | Low]

**Description:**

[What is the issue and why does it matter?]

**Location:**

- `path/to/file.rs` — relevant functions

**Fix Applied / Mitigation:**

[What was done or what mitigates the risk?]

**Verification:**

- [How to verify the fix works]

**Cross-References:**

- [CHANGELOG.md](CHANGELOG.md) → [version] → Fixed
- [GitHub Issue](https://github.com/OpenLedger-Foundation/Kora-Contract/issues/XXX)
```

---

## Release Checklist

Before releasing a new version:

1. ✓ All open findings are resolved or have a documented timeline
2. ✓ CHANGELOG.md reflects all fixes and new features
3. ✓ AUDIT_LOG.md is updated with resolution status
4. ✓ Code review and security sign-off obtained
5. ✓ All tests pass: `make fmt && make lint && cargo test --all`
6. ✓ WASM binaries built and hashes recorded in release notes

---

*Last updated: 2026-06-27*
