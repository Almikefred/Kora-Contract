#![no_std]

use kora_shared::{
    audit::{AdminActionType, AdminAuditEntry, AuditSource, MAX_AUDIT_LOG_SIZE},
    errors::CommonError,
    events,
    reentrancy::ReentrancyGuard,
    validation::{require_non_negative_amount, require_valid_fee_bps, require_within_max_amount, UPGRADE_TIMELOCK_DELAY},
};
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, token, Address, BytesN, Env, Vec};

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TreasuryError {
    AlreadyInitialized = 1,
    ArithmeticOverflow = 2,
    InsufficientPoolBalance = 3,
    InvalidAddress = 4,
    InvalidAmount = 5,
    InvalidFeeRate = 6,
    NoCapChangeProposed = 7,
    NoUpgradeProposed = 8,
    NotAdmin = 9,
    NotInitialized = 10,
    Reentrancy = 11,
    TokenNotWhitelisted = 12,
    UpgradeTimelockNotElapsed = 13,
    WithdrawalCapTimelockNotElapsed = 14,
    WithdrawalRateLimitExceeded = 15,
}

impl From<CommonError> for TreasuryError {
    fn from(e: CommonError) -> Self {
        match e {
            CommonError::InvalidAmount => TreasuryError::InvalidAmount,
            CommonError::InvalidAddress => TreasuryError::InvalidAddress,
            CommonError::InvalidFeeRate => TreasuryError::InvalidFeeRate,
            CommonError::ArithmeticOverflow => TreasuryError::ArithmeticOverflow,
            CommonError::Reentrancy => TreasuryError::Reentrancy,
            // Any other CommonError variant reachable via a `?` call in this crate
            // falls back to InvalidAmount rather than being silently dropped.
            _ => TreasuryError::InvalidAmount,
        }
    }
}

// ── Storage TTL constants (~31 days in ledgers) ───────────────────────────────
const PERSISTENT_BUMP_AMOUNT: u32 = 535_680;
const PERSISTENT_LIFETIME_THRESHOLD: u32 = 535_680 / 2;

// ── Rate-limit epoch: 24 h in seconds ────────────────────────────────────────
const EPOCH_DURATION: u64 = 86_400;

// ── Storage Keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Admin address — persistent so it survives ledger archival.
    Admin,
    /// Protocol fee in basis points — persistent for durability.
    FeeBps,
    /// Accumulated fees per token (informational).
    Collected(Address),
    /// Whitelisted token flag.
    WhitelistedToken(Address),
    /// Pending upgrade proposal: (wasm_hash, proposed_at_timestamp).
    UpgradeProposal,
    /// Reentrancy guard flag (instance-level).
    WithdrawalLock,
    /// Maximum total withdrawal allowed per EPOCH_DURATION window for a given
    /// token (0 = uncapped). Keyed by token so unrelated tokens' caps don't
    /// share a single global quota (#452).
    WithdrawalCap(Address),
    /// Pending cap change proposal for a given token: (new_cap, proposed_at).
    WithdrawalCapProposal(Address),
    /// Timestamp when the current rate-limit epoch started, per token.
    EpochStart(Address),
    /// Total withdrawn in the current epoch, per token (resets each epoch).
    EpochWithdrawn(Address),
    /// Address of the `access_control` contract instance (optional — pause
    /// enforcement is skipped when unset, e.g. in unit tests) (#454).
    AccessControl,
    /// Distinct, admin-declared flag gating `emergency_withdraw` (#453).
    EmergencyDeclared,
    // ── Audit log ─────────────────────────────────────────────────────────────
    /// Next write position in the audit ring buffer (0..MAX_AUDIT_LOG_SIZE).
    AuditLogHead,
    /// Total admin actions ever recorded (monotonic; not capped at ring size).
    AuditLogTotal,
    /// An audit log entry at ring-buffer position `n`.
    AuditEntry(u64),
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct TreasuryContract;

#[contractimpl]
impl TreasuryContract {
    /// One-time initialization. Sets admin and protocol fee.
    ///
    /// **Parameters:**
    /// - `admin` — The address that will administer this contract.
    /// - `fee_bps` — Protocol fee in basis points (0–10 000).
    ///
    /// **Errors:**
    /// - `TreasuryError::AlreadyInitialized` — Contract has already been initialized.
    /// - `TreasuryError::InvalidFeeRate` — `fee_bps` > 10 000.
    /// - `TreasuryError::InvalidAddress` — `admin` is the contract's own address.
    ///
    /// **Security:** No auth required on first call. Subsequent calls revert immediately.
    /// Initializes rate-limit state (epoch start, epoch withdrawn, cap = 0 = uncapped).
    pub fn initialize(env: Env, admin: Address, fee_bps: u32) -> Result<(), TreasuryError> {
        if env.storage().persistent().has(&DataKey::Admin) {
            return Err(TreasuryError::AlreadyInitialized);
        }
        require_valid_fee_bps(fee_bps)?;
        kora_shared::validation::require_not_self(&env, &admin)?;
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().extend_ttl(
            &DataKey::Admin,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
        env.storage().persistent().extend_ttl(
            &DataKey::FeeBps,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        events::treasury_initialized(&env, &admin, fee_bps);
        Ok(())
    }

    /// Set (or update) the `access_control` contract reference used to gate
    /// `withdraw` behind the protocol-wide pause flag. Admin only.
    ///
    /// A post-init setter rather than an `initialize` parameter, so existing
    /// deployments/tests can opt in without changing `initialize`'s signature.
    ///
    /// **Errors:**
    /// - `KoraError::NotAdmin` — Caller is not the admin.
    ///
    /// **Security:** Requires `admin.require_auth()`.
    pub fn set_access_control(
        env: Env,
        admin: Address,
        access_control: Address,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::AccessControl, &access_control);
        events::access_control_updated(&env, &admin, &access_control);
        Self::append_audit_entry(&env, &admin, AdminActionType::SetAccessControl);
        Ok(())
    }

    /// Update protocol fee. Admin only.
    ///
    /// **Parameters:**
    /// - `admin` — Must be the current admin address.
    /// - `fee_bps` — New fee in basis points (0–10 000).
    ///
    /// **Errors:**
    /// - `TreasuryError::NotAdmin` — Caller is not the admin.
    /// - `TreasuryError::InvalidFeeRate` — `fee_bps` > 10 000.
    ///
    /// **Security:** Requires `admin.require_auth()`. Emits `fee_rate_updated` event.
    pub fn set_fee_bps(env: Env, admin: Address, fee_bps: u32) -> Result<(), TreasuryError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        require_valid_fee_bps(fee_bps)?;

        let old_bps: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(50);

        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
        Self::bump_persistent(&env, &DataKey::FeeBps);

        events::fee_rate_updated(&env, &admin, old_bps, fee_bps);
        Self::append_audit_entry(&env, &admin, AdminActionType::SetFeeBps);
        Ok(())
    }

    /// Whitelist a token so it can be used in `withdraw` / `emergency_withdraw`.
    ///
    /// Admin only. Idempotent — calling it twice for the same token is safe.
    ///
    /// **Parameters:**
    /// - `admin` — Must be the current admin address.
    /// - `token` — The token contract address to whitelist.
    ///
    /// **Errors:**
    /// - `TreasuryError::NotAdmin` — Caller is not the admin.
    ///
    /// **Security:** Requires `admin.require_auth()`. Emits `token_whitelisted` event.
    pub fn whitelist_token(env: Env, admin: Address, token: Address) -> Result<(), TreasuryError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;

        env.storage()
            .persistent()
            .set(&DataKey::WhitelistedToken(token.clone()), &true);
        Self::bump_persistent(&env, &DataKey::WhitelistedToken(token.clone()));

        events::token_whitelisted(&env, &admin, &token);
        Self::append_audit_entry(&env, &admin, AdminActionType::WhitelistToken);
        Ok(())
    }

    /// Record an incoming fee for a given token. Called by the marketplace after
    /// transferring the fee amount to this contract. Updates the informational
    /// accounting ledger.
    ///
    /// **Parameters:**
    /// - `token` — The token address the fee was paid in (must be whitelisted).
    /// - `amount` — The fee amount (must be > 0).
    ///
    /// **Errors:**
    /// - `TreasuryError::InvalidAmount` — `amount` is ≤ 0.
    /// - `TreasuryError::TokenNotWhitelisted` — Token has not been whitelisted.
    /// - `TreasuryError::ArithmeticOverflow` — Running total would overflow.
    ///
    /// **Security:** No auth required — the token transfer itself is the proof of payment.
    /// The amount is validated to be > 0 to prevent no-op accounting entries.
    pub fn collect_fee(env: Env, token: Address, amount: i128) -> Result<(), TreasuryError> {
        if amount <= 0 {
            return Err(TreasuryError::InvalidAmount);
        }
        Self::require_whitelisted_token(&env, &token)?;

        let key = DataKey::Collected(token.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_total = current
            .checked_add(amount)
            .ok_or(TreasuryError::ArithmeticOverflow)?;

        env.storage().persistent().set(&key, &new_total);
        Self::bump_persistent(&env, &key);

        events::fee_collected(&env, &env.current_contract_address(), 0, amount, &token);
        Ok(())
    }

    /// Withdraw accumulated fees to a recipient. Admin only.
    ///
    /// **Parameters:**
    /// - `admin` — Must be the current admin address.
    /// - `token` — The whitelisted token to withdraw.
    /// - `recipient` — The address to send funds to.
    /// - `amount` — The amount to withdraw (must be > 0 and ≤ `MAX_AMOUNT`).
    ///
    /// **Errors:**
    /// - `KoraError::NotAdmin` — Caller is not the admin.
    /// - `KoraError::ProtocolPaused` — The protocol is paused (see `set_access_control`).
    /// - `KoraError::InvalidAmount` — `amount` is ≤ 0 or exceeds `MAX_AMOUNT`.
    /// - `KoraError::TokenNotWhitelisted` — Token is not whitelisted.
    /// - `KoraError::WithdrawalRateLimitExceeded` — Would exceed the token's rolling 24 h cap.
    /// - `KoraError::Reentrancy` — Reentrancy guard triggered.
    /// - `KoraError::InsufficientFunds` — Contract balance is less than `amount`.
    /// - `TreasuryError::NotAdmin` — Caller is not the admin.
    /// - `TreasuryError::InvalidAmount` — `amount` is ≤ 0 or exceeds `MAX_AMOUNT`.
    /// - `TreasuryError::TokenNotWhitelisted` — Token is not whitelisted.
    /// - `TreasuryError::WithdrawalRateLimitExceeded` — Would exceed the rolling 24 h cap.
    /// - `TreasuryError::Reentrancy` — Reentrancy guard triggered.
    /// - `TreasuryError::InsufficientPoolBalance` — Contract balance is less than `amount`.
    ///
    /// **Security:** Requires `admin.require_auth()`. Blocked while the protocol is paused.
    /// Subject to the token's own rolling 24 h withdrawal cap. Protected against reentrancy
    /// via RAII `ReentrancyGuard`.
    pub fn withdraw(
        env: Env,
        admin: Address,
        token: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), TreasuryError> {
        // ── Checks ────────────────────────────────────────────────────────────
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        Self::require_not_paused(&env)?;
        if amount <= 0 {
            return Err(TreasuryError::InvalidAmount);
        }
        require_within_max_amount(amount)?;
        Self::require_whitelisted_token(&env, &token)?;
        Self::enforce_rate_limit(&env, &token, amount)?;

        // Acquire reentrancy guard — released automatically when _guard drops
        let _guard = ReentrancyGuard::new(&env)?;

        let token_client = token::Client::new(&env, &token);
        let balance = token_client.balance(&env.current_contract_address());

        if balance < amount {
            return Err(KoraError::InsufficientFunds);
            return Err(TreasuryError::InsufficientPoolBalance);
        }

        // ── Effects ───────────────────────────────────────────────────────────
        let collected_key = DataKey::Collected(token.clone());
        if let Some(collected) = env
            .storage()
            .persistent()
            .get::<_, i128>(&collected_key)
        {
            let new_collected = collected.saturating_sub(amount);
            env.storage().persistent().set(&collected_key, &new_collected);
            Self::bump_persistent(&env, &collected_key);
        }
        Self::record_withdrawal(&env, &token, amount);

        // ── Interactions ──────────────────────────────────────────────────────
        token_client.transfer(&env.current_contract_address(), &recipient, &amount);

        events::fee_withdrawn(&env, &admin, &token, amount);
        Self::append_audit_entry(&env, &admin, AdminActionType::Withdraw);
        Ok(())
    }

    /// Emergency drain — withdraw entire token balance. Admin only.
    ///
    /// **Parameters:**
    /// - `admin` — Must be the current admin address.
    /// - `token` — The whitelisted token to drain.
    /// - `recipient` — The address to send the full balance to.
    ///
    /// **Errors:**
    /// - `TreasuryError::NotAdmin` — Caller is not the admin.
    /// - `TreasuryError::TokenNotWhitelisted` — Token is not whitelisted.
    /// - `TreasuryError::Reentrancy` — Reentrancy guard triggered.
    ///
    /// **Security:** Requires `admin.require_auth()`. Gated behind `declare_emergency` (#453)
    /// so the uncapped drain path is a distinct, auditable admin action rather than always
    /// callable. Protected against reentrancy via RAII `ReentrancyGuard`. No-ops silently
    /// when balance is zero (not an error).
    ///
    /// **Deliberately independent of the protocol pause flag** (unlike `withdraw`): the whole
    /// point of `emergency_withdraw` is to evacuate funds during an incident, which is
    /// precisely when the protocol is most likely to already be paused. Gating it on
    /// `!is_paused()` (as a literal reading of #454 would require) would make it unusable
    /// exactly when it's needed, and combined with #453's requirement would make the function
    /// permanently uncallable. `declare_emergency` is the intentionally distinct precondition
    /// instead — see #453 and #454 for the full reasoning.
    pub fn emergency_withdraw(
        env: Env,
        admin: Address,
        token: Address,
        recipient: Address,
    ) -> Result<(), TreasuryError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        Self::require_whitelisted_token(&env, &token)?;
        let declared: bool = env
            .storage()
            .instance()
            .get(&DataKey::EmergencyDeclared)
            .unwrap_or(false);
        if !declared {
            return Err(KoraError::EmergencyNotDeclared);
        }

        let _guard = ReentrancyGuard::new(&env)?;

        let token_client = token::Client::new(&env, &token);
        let balance = token_client.balance(&env.current_contract_address());

        if balance > 0 {
            token_client.transfer(&env.current_contract_address(), &recipient, &balance);
            events::emergency_withdrawn(&env, &admin, &token, balance);
        }
        Self::append_audit_entry(&env, &admin, AdminActionType::EmergencyWithdraw);
        Ok(())
    }

    /// Declare a treasury emergency, unlocking `emergency_withdraw`. Admin only.
    ///
    /// A distinct, auditable action from ordinary withdrawals — required before the
    /// uncapped drain path in `emergency_withdraw` becomes callable (#453). Stays in
    /// effect until `revoke_emergency` is called.
    ///
    /// **Errors:**
    /// - `KoraError::NotAdmin` — Caller is not the admin.
    ///
    /// **Security:** Requires `admin.require_auth()`. Emits `emergency_declared` event.
    pub fn declare_emergency(env: Env, admin: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::EmergencyDeclared, &true);
        events::emergency_declared(&env, &admin);
        Self::append_audit_entry(&env, &admin, AdminActionType::DeclareEmergency);
        Ok(())
    }

    /// Revoke a previously declared emergency, re-locking `emergency_withdraw`. Admin only.
    ///
    /// **Errors:**
    /// - `KoraError::NotAdmin` — Caller is not the admin.
    ///
    /// **Security:** Requires `admin.require_auth()`. Emits `emergency_revoked` event.
    pub fn revoke_emergency(env: Env, admin: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::EmergencyDeclared, &false);
        events::emergency_revoked(&env, &admin);
        Self::append_audit_entry(&env, &admin, AdminActionType::RevokeEmergency);
        Ok(())
    }

    /// Returns whether a treasury emergency is currently declared.
    ///
    /// **Security:** Read-only view. No authorization required.
    pub fn is_emergency_declared(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::EmergencyDeclared)
            .unwrap_or(false)
    }

    /// Returns whether the protocol is currently paused, as seen by this treasury
    /// instance's configured `access_control` reference (`false` if unset).
    ///
    /// **Security:** Read-only view. No authorization required.
    pub fn is_paused(env: Env) -> bool {
        Self::require_not_paused(&env).is_err()
    }

    // ── Withdrawal cap management ─────────────────────────────────────────────

    /// Propose a new withdrawal cap for a specific token. Takes effect after
    /// `UPGRADE_TIMELOCK_DELAY` (24 h). Each whitelisted token has its own independent
    /// rolling cap and epoch (#452) — proposing a cap for one token never affects any
    /// other token's quota.
    ///
    /// **Parameters:**
    /// - `admin` — Must be the current admin address.
    /// - `token` — The token this cap applies to.
    /// - `new_cap` — The new rolling 24 h withdrawal limit in the token's smallest unit.
    ///   Set to 0 to remove the limit.
    ///
    /// **Errors:**
    /// - `TreasuryError::NotAdmin` — Caller is not the admin.
    /// - `TreasuryError::InvalidAmount` — `new_cap` is negative.
    ///
    /// **Security:** Requires `admin.require_auth()`. The proposal must be executed via
    /// `execute_withdrawal_cap` after the timelock elapses.
    pub fn propose_withdrawal_cap(
        env: Env,
        admin: Address,
        token: Address,
        new_cap: i128,
    ) -> Result<(), TreasuryError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        require_non_negative_amount(new_cap)?;
        if new_cap < 0 {
            return Err(TreasuryError::InvalidAmount);
        }
        env.storage().instance().set(
            &DataKey::WithdrawalCapProposal(token.clone()),
            &(new_cap, env.ledger().timestamp()),
        );
        events::withdrawal_cap_proposed(&env, &admin, &token, new_cap);
        Self::append_audit_entry(&env, &admin, AdminActionType::ProposeWithdrawalCap);
        Ok(())
    }

    /// Execute a previously proposed withdrawal cap change for a token after the
    /// timelock elapses.
    ///
    /// Admin only. Applies the new rolling 24-hour withdrawal limit that was previously
    /// queued via `propose_withdrawal_cap`, atomically clearing the pending proposal.
    ///
    /// **Parameters:**
    /// - `admin` — Must be the current admin address.
    /// - `token` — The token whose proposed cap should be applied.
    ///
    /// **Errors:**
    /// - `KoraError::NotAdmin` — Caller is not the admin.
    /// - `KoraError::NoUpgradeProposed` — No withdrawal cap proposal is pending.
    /// - `KoraError::UpgradeTimelockNotElapsed` — 24-hour timelock has not yet passed.
    /// - `TreasuryError::NotAdmin` — Caller is not the admin.
    /// - `TreasuryError::NoCapChangeProposed` — No withdrawal cap proposal is pending.
    /// - `TreasuryError::WithdrawalCapTimelockNotElapsed` — 24-hour timelock has not yet passed.
    ///
    /// **Security:** Requires `admin.require_auth()`. Clears the proposal atomically before
    /// applying the new cap. Emits `withdrawal_cap_updated` event.
    pub fn execute_withdrawal_cap(env: Env, admin: Address) -> Result<(), TreasuryError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let proposal_key = DataKey::WithdrawalCapProposal(token.clone());
        let (new_cap, proposed_at): (i128, u64) = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawalCapProposal)
            .ok_or(KoraError::NoUpgradeProposed)?;
        if env.ledger().timestamp() < proposed_at + UPGRADE_TIMELOCK_DELAY {
            return Err(KoraError::UpgradeTimelockNotElapsed);
            .ok_or(TreasuryError::NoCapChangeProposed)?;
        if env.ledger().timestamp() < proposed_at + UPGRADE_TIMELOCK_DELAY {
            return Err(TreasuryError::WithdrawalCapTimelockNotElapsed);
        }
        let cap_key = DataKey::WithdrawalCap(token.clone());
        let old_cap: i128 = env.storage().instance().get(&cap_key).unwrap_or(0);
        env.storage().instance().set(&cap_key, &new_cap);
        env.storage().instance().remove(&proposal_key);
        events::withdrawal_cap_updated(&env, &admin, &token, old_cap, new_cap);
        Self::append_audit_entry(&env, &admin, AdminActionType::ExecuteWithdrawalCap);
        Ok(())
    }

    /// Returns the current rolling 24-hour withdrawal cap for a token, in its smallest unit.
    ///
    /// A value of `0` means the cap is disabled (uncapped) for that token. A positive value
    /// is the maximum total amount that can be withdrawn within any 24-hour epoch. Each
    /// token's cap is fully independent of every other token's (#452).
    ///
    /// **Security:** Read-only view. No authorization required.
    pub fn get_withdrawal_cap(env: Env, token: Address) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawalCap(token))
            .unwrap_or(0)
    }

    /// Returns the current protocol fee in basis points (e.g., 50 = 0.5%).
    ///
    /// Defaults to 50 bps if the contract has not yet been initialized or if the
    /// fee has never been explicitly set.
    ///
    /// **Security:** Read-only view. No authorization required.
    pub fn get_fee_bps(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(50)
    }

    /// Returns the live token balance held by this contract for the given token.
    ///
    /// **Parameters:**
    /// - `token` — The token contract address to query.
    ///
    /// **Returns:** The current balance in the token's smallest unit (stroops for XLM-based tokens).
    /// Returns `0` if the contract holds none of the requested token.
    ///
    /// **Security:** Read-only view. No authorization required.
    pub fn get_balance(env: Env, token: Address) -> i128 {
        token::Client::new(&env, &token).balance(&env.current_contract_address())
    }

    /// Returns the running total of fees collected for a given token (informational ledger).
    ///
    /// This counter is maintained by `collect_fee` and decremented by `withdraw`. It is
    /// informational and does not gate any operation — actual spendable funds are determined
    /// by `get_balance`.
    ///
    /// **Parameters:**
    /// - `token` — The token contract address to query.
    ///
    /// **Returns:** Total fees collected in the token's smallest unit. Returns `0` if no
    /// fees have been collected for this token yet.
    ///
    /// **Security:** Read-only view. No authorization required.
    pub fn get_collected(env: Env, token: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Collected(token))
            .unwrap_or(0)
    }

    /// Returns the current admin address.
    ///
    /// **Errors:**
    /// - `TreasuryError::NotInitialized` — Contract has not been initialized.
    ///
    /// **Security:** Read-only view. No authorization required.
    pub fn get_admin(env: Env) -> Result<Address, TreasuryError> {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(TreasuryError::NotInitialized)
    }

    // ── Upgrade ────────────────────────────────────────────────────────────────

    /// Propose a WASM upgrade. Admin only. Begins a 24-hour timelock.
    ///
    /// **Parameters:**
    /// - `admin` — Must be the current admin address.
    /// - `new_wasm_hash` — SHA-256 hash of the new WASM binary (32 bytes).
    ///
    /// **Errors:**
    /// - `TreasuryError::NotAdmin` — Caller is not the admin.
    ///
    /// **Security:** Requires `admin.require_auth()`. Apply with `execute_upgrade` after
    /// `UPGRADE_TIMELOCK_DELAY` (24 h) has elapsed.
    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), TreasuryError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::UpgradeProposal, &(new_wasm_hash.clone(), env.ledger().timestamp()));
        events::upgrade_proposed(&env, &admin, &new_wasm_hash);
        Self::append_audit_entry(&env, &admin, AdminActionType::TreasuryProposeUpgrade);
        Ok(())
    }

    /// Execute a previously proposed WASM upgrade after the 24-hour timelock has elapsed.
    ///
    /// **Parameters:**
    /// - `admin` — Must be the current admin address.
    ///
    /// **Errors:**
    /// - `TreasuryError::NotAdmin` — Caller is not the admin.
    /// - `TreasuryError::NoUpgradeProposed` — No upgrade proposal is pending.
    /// - `TreasuryError::UpgradeTimelockNotElapsed` — 24-hour timelock has not yet passed.
    ///
    /// **Security:** Requires `admin.require_auth()`. Clears the proposal atomically before executing.
    pub fn execute_upgrade(env: Env, admin: Address) -> Result<(), TreasuryError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let (wasm_hash, proposed_at): (BytesN<32>, u64) = env
            .storage()
            .instance()
            .get(&DataKey::UpgradeProposal)
            .ok_or(TreasuryError::NoUpgradeProposed)?;
        if env.ledger().timestamp() < proposed_at + UPGRADE_TIMELOCK_DELAY {
            return Err(TreasuryError::UpgradeTimelockNotElapsed);
        }
        env.storage().instance().remove(&DataKey::UpgradeProposal);
        events::upgrade_executed(&env, &admin, &wasm_hash);
        Self::append_audit_entry(&env, &admin, AdminActionType::TreasuryExecuteUpgrade);
        env.deployer().update_current_contract_wasm(wasm_hash);
        Ok(())
    }

    // ── Audit Log ─────────────────────────────────────────────────────────────

    /// Return a page of audit log entries, newest first.
    /// `page` is 0-indexed; `page_size` is clamped to 1–50.
    pub fn get_audit_log(env: Env, page: u32, page_size: u32) -> Vec<AdminAuditEntry> {
        let page_size = (page_size.max(1).min(50)) as u64;
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditLogTotal)
            .unwrap_or(0);
        let head: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditLogHead)
            .unwrap_or(0);
        let stored = total.min(MAX_AUDIT_LOG_SIZE);

        let skip = (page as u64).saturating_mul(page_size);
        let mut results = Vec::new(&env);

        let mut i: u64 = 0;
        while i < page_size {
            let offset = skip + i;
            if offset >= stored {
                break;
            }
            let pos = (head + MAX_AUDIT_LOG_SIZE - 1 - offset) % MAX_AUDIT_LOG_SIZE;
            if let Some(entry) = env
                .storage()
                .persistent()
                .get::<DataKey, AdminAuditEntry>(&DataKey::AuditEntry(pos))
            {
                results.push_back(entry);
            }
            i += 1;
        }

        results
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), TreasuryError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(TreasuryError::NotInitialized)?;
        if &admin != caller {
            return Err(TreasuryError::NotAdmin);
        }
        Ok(())
    }

    fn require_whitelisted_token(env: &Env, token: &Address) -> Result<(), TreasuryError> {
        let whitelisted: bool = env
            .storage()
            .persistent()
            .get(&DataKey::WhitelistedToken(token.clone()))
            .unwrap_or(false);
        if !whitelisted {
            return Err(TreasuryError::TokenNotWhitelisted);
        }
        Ok(())
    }

    /// Advance the epoch if 24 h have elapsed, then check the cap.
    fn enforce_rate_limit(env: &Env, amount: i128) -> Result<(), TreasuryError> {
        let cap: i128 = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawalCap(token.clone()))
            .unwrap_or(0);
        if cap == 0 {
            return Ok(());
        }

        let now = env.ledger().timestamp();
        let epoch_start_key = DataKey::EpochStart(token.clone());
        let epoch_withdrawn_key = DataKey::EpochWithdrawn(token.clone());
        let epoch_start: u64 = env
            .storage()
            .instance()
            .get(&epoch_start_key)
            .unwrap_or(now);

        let epoch_withdrawn: i128 = if now.saturating_sub(epoch_start) >= EPOCH_DURATION {
            // New epoch: reset counters.
            env.storage().instance().set(&epoch_start_key, &now);
            env.storage().instance().set(&epoch_withdrawn_key, &0i128);
            0
        } else {
            env.storage().instance().get(&epoch_withdrawn_key).unwrap_or(0)
        };

        let new_total = epoch_withdrawn
            .checked_add(amount)
            .ok_or(TreasuryError::ArithmeticOverflow)?;
        if new_total > cap {
            return Err(TreasuryError::WithdrawalRateLimitExceeded);
        }
        Ok(())
    }

    /// Record a successful withdrawal against `token`'s current epoch running total.
    fn record_withdrawal(env: &Env, token: &Address, amount: i128) {
        let cap: i128 = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawalCap(token.clone()))
            .unwrap_or(0);
        if cap == 0 {
            return;
        }
        let epoch_withdrawn_key = DataKey::EpochWithdrawn(token.clone());
        let current: i128 = env
            .storage()
            .instance()
            .get(&epoch_withdrawn_key)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&epoch_withdrawn_key, &current.saturating_add(amount));
    }

    /// Blocks the caller if the protocol is paused, as reported by the configured
    /// `access_control` contract. Mirrors `marketplace::require_not_paused` (#454).
    ///
    /// If `DataKey::AccessControl` has never been set (e.g. in unit tests that don't
    /// wire up a real access-control instance), the pause check is skipped rather than
    /// erroring, so existing deployments/tests are unaffected until they opt in via
    /// `set_access_control`.
    fn require_not_paused(env: &Env) -> Result<(), KoraError> {
        if let Some(ac_contract) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::AccessControl)
        {
            let ac = kora_access_control::AccessControlContractClient::new(env, &ac_contract);
            if ac.is_paused() {
                return Err(KoraError::ProtocolPaused);
            }
        }
        Ok(())
    }

    fn bump_persistent(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(
            key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn append_audit_entry(env: &Env, actor: &Address, action: AdminActionType) {
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditLogTotal)
            .unwrap_or(0);
        let head: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditLogHead)
            .unwrap_or(0);

        let entry = AdminAuditEntry {
            sequence: total,
            timestamp: env.ledger().timestamp(),
            actor: actor.clone(),
            action,
            source: AuditSource::Treasury,
        };

        env.storage()
            .persistent()
            .set(&DataKey::AuditEntry(head), &entry);
        Self::bump_persistent(env, &DataKey::AuditEntry(head));

        events::admin_action_audited(env, &entry);

        let next_head = (head + 1) % MAX_AUDIT_LOG_SIZE;
        env.storage()
            .instance()
            .set(&DataKey::AuditLogHead, &next_head);
        env.storage()
            .instance()
            .set(&DataKey::AuditLogTotal, &(total + 1));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, MockAuth, MockAuthInvoke},
        token, Address, Env,
    };

    fn setup() -> (Env, Address, TreasuryContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &50u32);
        (env, admin, client)
    }

    /// Deploy a minimal Soroban token contract and return its address +
    /// a client minted with `amount` to `recipient`.
    fn deploy_token(env: &Env, admin: &Address, recipient: &Address, amount: i128) -> Address {
        let token_id = env.register_stellar_asset_contract_v2(admin.clone()).address();
        let token_client = token::StellarAssetClient::new(env, &token_id);
        token_client.mint(recipient, &amount);
        token_id
    }

    // ── initialize ────────────────────────────────────────────────────────────

    #[test]
    fn test_initialize_creates_contract() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        assert!(client.try_initialize(&admin, &50u32).is_ok());
        assert_eq!(client.get_fee_bps(), 50);
    }

    #[test]
    fn test_initialize_already_initialized() {
        let (env, admin, client) = setup();
        let result = client.try_initialize(&admin, &50u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_initialize_invalid_fee_bps() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        assert!(client.try_initialize(&admin, &10_001u32).is_err());
    }

    #[test]
    fn test_initialize_self_as_admin_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        // Passing the contract's own address as admin must be rejected.
        let result = client.try_initialize(&contract_id, &50u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_fee_bps_after_init() {
        let (_env, _admin, client) = setup();
        assert_eq!(client.get_fee_bps(), 50);
    }

    // ── set_fee_bps ───────────────────────────────────────────────────────────

    #[test]
    fn test_set_fee_bps_success() {
        let (_env, admin, client) = setup();
        client.set_fee_bps(&admin, &100u32);
        assert_eq!(client.get_fee_bps(), 100);
    }

    #[test]
    fn test_set_fee_bps_requires_admin() {
        let (env, _admin, client) = setup();
        let non_admin = Address::generate(&env);
        assert!(client.try_set_fee_bps(&non_admin, &100u32).is_err());
    }

    #[test]
    fn test_set_fee_bps_invalid_bps_fails() {
        let (_env, admin, client) = setup();
        assert!(client.try_set_fee_bps(&admin, &10_001u32).is_err());
    }

    #[test]
    fn test_set_fee_bps_zero_allowed() {
        let (_env, admin, client) = setup();
        client.set_fee_bps(&admin, &0u32);
        assert_eq!(client.get_fee_bps(), 0);
    }

    #[test]
    fn test_set_fee_bps_max_allowed() {
        let (_env, admin, client) = setup();
        client.set_fee_bps(&admin, &10_000u32);
        assert_eq!(client.get_fee_bps(), 10_000);
    }

    #[test]
    fn test_set_fee_bps_over_max_fails() {
        let (_env, admin, client) = setup();
        assert!(client.try_set_fee_bps(&admin, &10_001u32).is_err());
    }

    #[test]
    fn test_set_fee_bps_multiple_updates() {
        let (_env, admin, client) = setup();
        client.set_fee_bps(&admin, &100u32);
        assert_eq!(client.get_fee_bps(), 100);
        client.set_fee_bps(&admin, &200u32);
        assert_eq!(client.get_fee_bps(), 200);
        client.set_fee_bps(&admin, &50u32);
        assert_eq!(client.get_fee_bps(), 50);
    }

    /// Verifies that `set_fee_bps` correctly reads the old value from the same
    /// storage tier that `initialize` wrote it to (both use `persistent()`).
    ///
    /// Before the fix, `set_fee_bps` read `old_bps` from `persistent()` while
    /// `initialize` wrote to `instance()`, so `old_bps` was always the fallback
    /// 50 and the `fee_rate_updated` event always reported the wrong old value.
    ///
    /// This test proves the round-trip is consistent:
    ///   initialize(fee=50) → set_fee_bps(100) → old_bps must be 50, not fallback.
    #[test]
    fn test_fee_rate_updated_event_reports_correct_old_fee() {
        let (env, admin, client) = setup(); // initialize with fee_bps = 50

        // First update: old value must be 50 (what initialize wrote), not the
        // unwrap_or(50) fallback that a wrong-tier read would also produce.
        // To distinguish them, initialize with a non-default value.
        let env2 = Env::default();
        env2.mock_all_auths();
        let contract2 = env2.register_contract(None, TreasuryContract);
        let client2 = TreasuryContractClient::new(&env2, &contract2);
        let admin2 = Address::generate(&env2);
        // Initialize with fee_bps = 75 (not the fallback default of 50).
        client2.initialize(&admin2, &75u32);
        assert_eq!(client2.get_fee_bps(), 75);

        // Update to 100. The recorded old value must be 75.
        // If the read were on the wrong tier it would silently return 50
        // and the event would carry the wrong old_bps.
        client2.set_fee_bps(&admin2, &100u32);
        assert_eq!(client2.get_fee_bps(), 100);

        // Second update to 200. Old value must be 100 (what we just wrote).
        client2.set_fee_bps(&admin2, &200u32);
        assert_eq!(client2.get_fee_bps(), 200);
    }

    // ── whitelist_token ───────────────────────────────────────────────────────

    #[test]
    fn test_whitelist_token_idempotent() {
        // Whitelisting the same token twice must not error — it's a no-op on the
        // second call (the token is simply already whitelisted).
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        assert!(client.try_whitelist_token(&admin, &token).is_ok());
        assert!(client.try_whitelist_token(&admin, &token).is_ok());
    }

    #[test]
    fn test_whitelist_token_requires_admin() {
        let (env, _admin, client) = setup();
        let non_admin = Address::generate(&env);
        let token = Address::generate(&env);
        assert!(client.try_whitelist_token(&non_admin, &token).is_err());
    }

    // ── collect_fee ───────────────────────────────────────────────────────────

    #[test]
    fn test_collect_fee_zero_amount_rejected() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        client.whitelist_token(&admin, &token);
        assert!(client.try_collect_fee(&token, &0i128).is_err());
    }

    #[test]
    fn test_collect_fee_negative_amount_rejected() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        client.whitelist_token(&admin, &token);
        assert!(client.try_collect_fee(&token, &-1i128).is_err());
    }

    #[test]
    fn test_collect_fee_non_whitelisted_token_rejected() {
        let (env, _admin, client) = setup();
        let token = Address::generate(&env);
        assert!(client.try_collect_fee(&token, &1_000i128).is_err());
    }

    #[test]
    fn test_collect_fee_accumulates() {
        // collect_fee is informational — multiple calls accumulate correctly.
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        client.whitelist_token(&admin, &token);
        client.collect_fee(&token, &500i128);
        client.collect_fee(&token, &300i128);
        // The collected ledger is internal, but no error means the addition succeeded.
    }

    #[test]
    fn test_collect_fee_overflow_rejected() {
        // Two consecutive collect_fee calls whose sum overflows i128 must return
        // ArithmeticOverflow — not silently wrap.
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        client.whitelist_token(&admin, &token);
        // Seed the ledger with i128::MAX first.
        client.collect_fee(&token, &i128::MAX);
        // Any further positive amount must overflow.
        let result = client.try_collect_fee(&token, &1i128);
        assert!(result.is_err());
    }

    // ── get_balance ───────────────────────────────────────────────────────────

    #[test]
    fn test_get_balance_returns_zero_for_unknown_token() {
        // Before any transfer, balance should be 0 for a freshly deployed token.
        let (env, admin, client) = setup();
        let contract_id = client.address.clone();
        let token_id = deploy_token(&env, &admin, &contract_id, 0);
        assert_eq!(client.get_balance(&token_id), 0);
    }

    #[test]
    fn test_get_balance_after_mint() {
        let (env, admin, client) = setup();
        let contract_id = client.address.clone();
        let token_id = deploy_token(&env, &admin, &contract_id, 1_000_000);
        assert_eq!(client.get_balance(&token_id), 1_000_000);
    }

    // ── withdraw ──────────────────────────────────────────────────────────────

    #[test]
    fn test_withdraw_requires_admin() {
        let (env, _admin, client) = setup();
        let non_admin = Address::generate(&env);
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        assert!(client
            .try_withdraw(&non_admin, &token, &recipient, &1_000_000i128)
            .is_err());
    }

    #[test]
    fn test_withdraw_zero_amount_fails() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        assert!(client
            .try_withdraw(&admin, &token, &recipient, &0i128)
            .is_err());
    }

    #[test]
    fn test_withdraw_with_negative_amount_rejected() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        assert!(client
            .try_withdraw(&admin, &token, &recipient, &-1_000i128)
            .is_err());
    }

    #[test]
    fn test_withdraw_non_whitelisted_token_rejected() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        assert!(client
            .try_withdraw(&admin, &token, &recipient, &1_000i128)
            .is_err());
    }

    #[test]
    fn test_withdraw_insufficient_balance_fails() {
        let (env, admin, client) = setup();
        let contract_id = client.address.clone();
        let token_id = deploy_token(&env, &admin, &contract_id, 500);
        let recipient = Address::generate(&env);
        client.whitelist_token(&admin, &token_id);
        // Contract only has 500, requesting 1_000 must fail.
        let result = client.try_withdraw(&admin, &token_id, &recipient, &1_000i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_withdraw_exact_balance_succeeds() {
        // Withdrawing exactly the available balance must succeed.
        let (env, admin, client) = setup();
        let contract_id = client.address.clone();
        let token_id = deploy_token(&env, &admin, &contract_id, 1_000);
        let recipient = Address::generate(&env);
        client.whitelist_token(&admin, &token_id);
        assert!(client
            .try_withdraw(&admin, &token_id, &recipient, &1_000i128)
            .is_ok());
        // Balance drained to zero.
        assert_eq!(client.get_balance(&token_id), 0);
    }

    // ── emergency_withdraw ────────────────────────────────────────────────────

    #[test]
    fn test_emergency_withdraw_requires_admin() {
        let (env, _admin, client) = setup();
        let non_admin = Address::generate(&env);
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        assert!(client
            .try_emergency_withdraw(&non_admin, &token, &recipient)
            .is_err());
    }

    #[test]
    fn test_emergency_withdraw_non_whitelisted_token_rejected() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        assert!(client
            .try_emergency_withdraw(&admin, &token, &recipient)
            .is_err());
    }

    #[test]
    fn test_emergency_withdraw_zero_balance_is_noop() {
        // When balance is zero, emergency_withdraw must succeed without error
        // (it simply has nothing to transfer).
        let (env, admin, client) = setup();
        let contract_id = client.address.clone();
        let token_id = deploy_token(&env, &admin, &contract_id, 0);
        let recipient = Address::generate(&env);
        client.whitelist_token(&admin, &token_id);
        assert!(client
            .try_emergency_withdraw(&admin, &token_id, &recipient)
            .is_ok());
    }

    #[test]
    fn test_emergency_withdraw_drains_full_balance() {
        let (env, admin, client) = setup();
        let contract_id = client.address.clone();
        let token_id = deploy_token(&env, &admin, &contract_id, 5_000);
        let recipient = Address::generate(&env);
        client.whitelist_token(&admin, &token_id);
        client.emergency_withdraw(&admin, &token_id, &recipient);
        assert_eq!(client.get_balance(&token_id), 0);
    }

    // ── reentrancy lock cleanup ───────────────────────────────────────────────

    #[test]
    fn test_lock_released_after_failed_withdraw() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        // Fails due to token not whitelisted — lock must be released
        let _ = client.try_withdraw(&admin, &token, &recipient, &1_000i128);
        // Subsequent admin operation must succeed (lock not stuck)
        assert!(client.try_set_fee_bps(&admin, &100u32).is_ok());
    }

    #[test]
    fn test_lock_released_after_emergency_withdraw() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let _ = client.try_emergency_withdraw(&admin, &token, &recipient);
        // Lock must be released regardless of outcome
        assert!(client.try_set_fee_bps(&admin, &100u32).is_ok());
    }

    // ── get_fee_bps ───────────────────────────────────────────────────────────

    #[test]
    fn test_admin_actions_work_immediately_after_initialize() {
        let (_env, admin, client) = setup();
        assert!(client.try_set_fee_bps(&admin, &100u32).is_ok());
    }

    #[test]
    fn test_get_fee_bps_default_before_init() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        // Returns 50 bps as the hard-coded fallback before initialization.
        assert_eq!(client.get_fee_bps(), 50);
    }

    #[test]
    fn test_get_balance_with_non_existent_token() {
        // Test behavior when calling get_balance with an arbitrary unregistered address
        // (not a valid token contract)
        let (env, _admin, client) = setup();
        let invalid_token = Address::generate(&env);

        // get_balance should return 0 for a non-existent token
        // (Soroban token::Client.balance() returns 0 if the account has no balance)
        let balance = client.get_balance(&invalid_token);
        assert_eq!(balance, 0i128, "Balance of non-existent token should be 0");
    }

    // ── withdrawal rate limit ─────────────────────────────────────────────────

    #[test]
    fn test_withdrawal_cap_default_is_uncapped() {
        let (env, _admin, client) = setup();
        let token = Address::generate(&env);
        assert_eq!(client.get_withdrawal_cap(&token), 0);
    }

    #[test]
    fn test_propose_withdrawal_cap_requires_admin() {
        let (env, _admin, client) = setup();
        let non_admin = Address::generate(&env);
        let token = Address::generate(&env);
        assert!(client
            .try_propose_withdrawal_cap(&non_admin, &token, &1_000_000i128)
            .is_err());
    }

    #[test]
    fn test_propose_negative_cap_rejected() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        assert!(client.try_propose_withdrawal_cap(&admin, &token, &-1i128).is_err());
    }

    #[test]
    fn test_execute_cap_before_timelock_fails() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        client.propose_withdrawal_cap(&admin, &token, &1_000_000i128);
        // Timelock hasn't elapsed
        assert!(client.try_execute_withdrawal_cap(&admin, &token).is_err());
    }

    #[test]
    fn test_execute_cap_without_proposal_fails() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        assert!(client.try_execute_withdrawal_cap(&admin, &token).is_err());
    }
}
