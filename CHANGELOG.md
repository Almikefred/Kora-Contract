# Kora Protocol — Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **#283 Verifier-delegated sub-accounts** — `risk_registry` now supports a primary verifier delegating action rights to N sub-accounts via `add_sub_account` / `remove_sub_account`. All SME registrations and score updates performed by a sub-account are attributed to the primary verifier for reputation and staking purposes. The primary verifier is stored in `SmeProfile.verifier` regardless of which signer performed the action. Sub-accounts cannot themselves be primary verifiers, and an address can only be a sub-account of one primary at a time.
- **#280 Storage rent/TTL cost model guide** — new `docs/storage-rent-cost-model.md` explains Soroban's three storage tiers (persistent / instance / temporary), the TTL constants used in each Kora contract, which keys are most expensive at scale, worked cost projections at 1 000 and 10 000 active invoices, and keeper-bot / archival responsibilities.
- **#276 Treasury contract documentation** — new `docs/treasury.md` covers the full `fee_bps` lifecycle, `withdraw` and `emergency_withdraw` flows with step-by-step ordering, the reentrancy guard design, the rolling 24-hour withdrawal rate-limit, the two-step cap/upgrade timelock, a complete public API table, the storage layout, and a threat-model / security analysis.

### Fixed
- **#343 Duplicate `KoraError` discriminant 95** *(breaking ABI change)* — `EmptyBytes` and `Reentrancy` previously both used discriminant 95, causing any reentrancy violation to be silently decoded as `EmptyBytes` by off-chain clients and preventing the crate from compiling (E0081). Discriminants are now unique: `NoContribution = 95`, `NotInitialized = 96`, `EmptyBytes = 97`, `Reentrancy = 98`. **Clients that pattern-match on `KoraError::Reentrancy` by its raw u32 value must update their discriminant from 95 to 98.**

### Changed
- **Removed duplicate sme_invoice_counted event** — use sme_invoice_count_incremented instead across all SME profile tracking (see `contracts/shared/src/events.rs` and AUDIT_LOG.md)

### Planned
- Multisig admin with timelock
- Contract upgrade mechanism
- Secondary market for pool positions
- Keeper network for TTL management
- On-chain FX oracle integration

---

## [0.1.0] — 2026-05-18

### Added
- `invoice_nft` contract — mint, status transitions, invoice NFT data model
- `marketplace` contract — list, fund, cancel, fee collection, whitelist
- `financing_pool` contract — fund custody, position tracking, repayment, yield distribution, default handling
- `treasury` contract — fee accumulation, admin withdrawal, emergency drain
- `risk_registry` contract — verifier management, SME profiles, debtor scoring
- `access_control` contract — pause/unpause, role management, admin transfer
- `shared` library — types, errors, events, validation utilities
- Integration test suite covering full invoice lifecycle and edge cases
- Deployment scripts for testnet and mainnet
- Makefile with build, test, lint, and deploy targets
- README, CONTRIBUTING, ARCHITECTURE, CONTRACTS, SECURITY documentation
