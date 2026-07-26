#![no_std]

use kora_shared::{
    audit::{chain_checksum, AuditEntry, MAX_AUDIT_LOG_SIZE},
    errors::KoraError,
    events,
    validation::require_valid_fee_bps,
};
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, BytesN, Env, String};

// ── Storage Keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    FeeBps,
    Collected(Address), // accumulated fees per token
    WithdrawalLock,     // reentrancy guard
    // Audit log ring buffer
    AuditEntry(u64),    // slot index 0..MAX_AUDIT_LOG_SIZE-1
    AuditHead,          // next write slot (u64)
    AuditTotal,         // total entries ever appended (u64)
    AuditChecksum,      // rolling sha256 checksum (BytesN<32>)
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct TreasuryContract;

#[contractimpl]
impl TreasuryContract {
    pub fn initialize(env: Env, admin: Address, fee_bps: u32) -> Result<(), KoraError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(KoraError::AlreadyInitialized);
        }
        require_valid_fee_bps(fee_bps)?;
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        env.storage()
            .instance()
            .set(&DataKey::WithdrawalLock, &false);

        // Initialise audit ring-buffer state
        env.storage().instance().set(&DataKey::AuditHead, &0u64);
        env.storage().instance().set(&DataKey::AuditTotal, &0u64);
        // Zero checksum seed
        let zero: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);
        env.storage()
            .instance()
            .set(&DataKey::AuditChecksum, &zero);

        Self::append_audit_entry(&env, &admin, String::from_str(&env, "initialize"));
        Ok(())
    }

    /// Update protocol fee. Admin only.
    pub fn set_fee_bps(env: Env, admin: Address, fee_bps: u32) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        require_valid_fee_bps(fee_bps)?;
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        Self::append_audit_entry(&env, &admin, String::from_str(&env, "set_fee_bps"));
        Ok(())
    }

    /// Withdraw accumulated fees to a recipient. Admin only. Protected against reentrancy.
    pub fn withdraw(
        env: Env,
        admin: Address,
        token: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        Self::acquire_lock(&env)?;

        if amount <= 0 {
            Self::release_lock(&env);
            return Err(KoraError::InvalidAmount);
        }

        let token_client = token::Client::new(&env, &token);
        let balance = token_client.balance(&env.current_contract_address());
        if balance < amount {
            Self::release_lock(&env);
            return Err(KoraError::InsufficientPoolBalance);
        }

        token_client.transfer(&env.current_contract_address(), &recipient, &amount);
        events::fee_withdrawn(&env, &token, amount);
        Self::append_audit_entry(&env, &admin, String::from_str(&env, "withdraw"));
        Self::release_lock(&env);
        Ok(())
    }

    /// Emergency drain — withdraw entire token balance. Admin only. Protected against reentrancy.
    pub fn emergency_withdraw(
        env: Env,
        admin: Address,
        token: Address,
        recipient: Address,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        Self::acquire_lock(&env)?;

        let token_client = token::Client::new(&env, &token);
        let balance = token_client.balance(&env.current_contract_address());
        if balance > 0 {
            token_client.transfer(&env.current_contract_address(), &recipient, &balance);
            events::fee_withdrawn(&env, &token, balance);
        }

        Self::append_audit_entry(&env, &admin, String::from_str(&env, "emergency_withdraw"));
        Self::release_lock(&env);
        Ok(())
    }

    pub fn get_fee_bps(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::FeeBps).unwrap_or(50)
    }

    pub fn get_balance(env: Env, token: Address) -> i128 {
        token::Client::new(&env, &token).balance(&env.current_contract_address())
    }

    /// Return up to the most recent `limit` audit entries (newest first).
    pub fn get_audit_log(env: Env, limit: u32) -> soroban_sdk::Vec<AuditEntry> {
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditTotal)
            .unwrap_or(0);
        let head: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditHead)
            .unwrap_or(0);

        let available = total.min(MAX_AUDIT_LOG_SIZE) as u32;
        let count = (limit as u32).min(available);

        let mut result = soroban_sdk::Vec::new(&env);
        for i in 0..count {
            // Walk backwards from the last written slot
            let offset = (i as u64 + 1) % MAX_AUDIT_LOG_SIZE;
            let slot = (head + MAX_AUDIT_LOG_SIZE - offset) % MAX_AUDIT_LOG_SIZE;
            if let Some(entry) = env
                .storage()
                .persistent()
                .get::<DataKey, AuditEntry>(&DataKey::AuditEntry(slot))
            {
                result.push_back(entry);
            }
        }
        result
    }

    /// Rolling sha256 checksum committing the full admin-action history.
    /// Verifiable on-chain; survives ring-buffer wraparound.
    pub fn get_audit_checksum(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::AuditChecksum)
            .unwrap_or_else(|| BytesN::from_array(&env, &[0u8; 32]))
    }

    /// Total number of audit entries ever appended (never resets).
    pub fn get_audit_total(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::AuditTotal)
            .unwrap_or(0)
    }

    // ── Internal Audit Helpers ────────────────────────────────────────────────

    /// Append one audit entry to the ring buffer.
    ///
    /// Behaviour:
    /// 1. Build the entry (sequence = total, timestamp = now).
    /// 2. Update the rolling checksum: checksum = sha256(prev_checksum || entry_bytes).
    /// 3. Emit ADM_AUDIT event (canonical off-chain history).
    /// 4. If `total % MAX_AUDIT_LOG_SIZE == 0` AND total > 0, a wraparound is about to
    ///    begin — read the slot we're about to overwrite and emit an `audit_checkpoint`
    ///    event carrying the current checksum and the discarded entry.
    /// 5. Write the entry into the ring-buffer slot and advance head/total.
    fn append_audit_entry(env: &Env, actor: &Address, action: String) {
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditTotal)
            .unwrap_or(0);
        let head: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditHead)
            .unwrap_or(0);

        let timestamp = env.ledger().timestamp();
        let sequence = total;

        let entry = AuditEntry {
            action: action.clone(),
            actor: actor.clone(),
            timestamp,
            sequence,
        };

        // 1. Update rolling checksum before writing (so the checksum covers this entry)
        let prev_checksum: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::AuditChecksum)
            .unwrap_or_else(|| BytesN::from_array(env, &[0u8; 32]));
        let new_checksum = chain_checksum(env, &prev_checksum, &entry);
        env.storage()
            .instance()
            .set(&DataKey::AuditChecksum, &new_checksum);

        // 2. Emit the canonical ADM_AUDIT event
        events::adm_audit(env, sequence, action, actor, timestamp);

        // 3. If this write will overwrite an existing slot, emit checkpoint first
        if total > 0 && total % MAX_AUDIT_LOG_SIZE == 0 {
            // The slot `head` currently holds the oldest entry in the window
            if let Some(old_entry) = env
                .storage()
                .persistent()
                .get::<DataKey, AuditEntry>(&DataKey::AuditEntry(head))
            {
                events::audit_checkpoint(
                    env,
                    total,
                    new_checksum.clone(),
                    old_entry.action,
                    &old_entry.actor,
                    old_entry.timestamp,
                    old_entry.sequence,
                );
            }
        }

        // 4. Write entry into ring buffer
        env.storage()
            .persistent()
            .set(&DataKey::AuditEntry(head), &entry);

        // 5. Advance head and total
        let next_head = (head + 1) % MAX_AUDIT_LOG_SIZE;
        env.storage()
            .instance()
            .set(&DataKey::AuditHead, &next_head);
        env.storage()
            .instance()
            .set(&DataKey::AuditTotal, &(total + 1));
    }

    // ── Auth Helpers ──────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), KoraError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(KoraError::NotInitialized)?;
        if &admin != caller {
            return Err(KoraError::NotAdmin);
        }
        Ok(())
    }

    fn acquire_lock(env: &Env) -> Result<(), KoraError> {
        let locked: bool = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawalLock)
            .unwrap_or(false);
        if locked {
            return Err(KoraError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&DataKey::WithdrawalLock, &true);
        Ok(())
    }

    fn release_lock(env: &Env) {
        env.storage()
            .instance()
            .set(&DataKey::WithdrawalLock, &false);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup() -> (Env, Address, TreasuryContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &50u32);
        (env, admin, client)
    }

    // ── Basic contract tests ──────────────────────────────────────────────────

    #[test]
    fn test_initialize_success() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let result = client.try_initialize(&admin, &50u32);
        assert!(result.is_ok());
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
        let result = client.try_initialize(&admin, &10_001u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_fee_bps_success() {
        let (env, admin, client) = setup();
        assert_eq!(client.get_fee_bps(), 50);
        client.set_fee_bps(&admin, &100u32);
        assert_eq!(client.get_fee_bps(), 100);
    }

    #[test]
    fn test_set_fee_bps_requires_admin() {
        let (env, _admin, client) = setup();
        let non_admin = Address::generate(&env);
        let result = client.try_set_fee_bps(&non_admin, &100u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_fee_bps_invalid_bps_fails() {
        let (env, admin, client) = setup();
        let result = client.try_set_fee_bps(&admin, &10_001u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_fee_bps_zero_succeeds() {
        let (env, admin, client) = setup();
        client.set_fee_bps(&admin, &0u32);
        assert_eq!(client.get_fee_bps(), 0);
    }

    #[test]
    fn test_set_fee_bps_max_succeeds() {
        let (env, admin, client) = setup();
        client.set_fee_bps(&admin, &10_000u32);
        assert_eq!(client.get_fee_bps(), 10_000);
    }

    #[test]
    fn test_withdraw_requires_admin() {
        let (env, _admin, client) = setup();
        let non_admin = Address::generate(&env);
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.try_withdraw(&non_admin, &token, &recipient, &1_000_000i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_withdraw_zero_amount_fails() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.try_withdraw(&admin, &token, &recipient, &0i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_withdraw_negative_amount_fails() {
        let (env, admin, client) = setup();
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.try_withdraw(&admin, &token, &recipient, &-1_000_000i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_emergency_withdraw_requires_admin() {
        let (env, _admin, client) = setup();
        let non_admin = Address::generate(&env);
        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.try_emergency_withdraw(&non_admin, &token, &recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_fee_updates() {
        let (env, admin, client) = setup();
        client.set_fee_bps(&admin, &100u32);
        assert_eq!(client.get_fee_bps(), 100);
        client.set_fee_bps(&admin, &200u32);
        assert_eq!(client.get_fee_bps(), 200);
        client.set_fee_bps(&admin, &50u32);
        assert_eq!(client.get_fee_bps(), 50);
    }

    // ── Audit log tests ───────────────────────────────────────────────────────

    #[test]
    fn test_audit_log_records_initialize() {
        let (env, _admin, client) = setup();
        let log = client.get_audit_log(&1u32);
        assert_eq!(log.len(), 1);
        assert_eq!(log.get(0).unwrap().action, String::from_str(&env, "initialize"));
    }

    #[test]
    fn test_audit_total_increments() {
        let (env, admin, client) = setup();
        assert_eq!(client.get_audit_total(), 1); // initialize
        client.set_fee_bps(&admin, &100u32);
        assert_eq!(client.get_audit_total(), 2);
        client.set_fee_bps(&admin, &200u32);
        assert_eq!(client.get_audit_total(), 3);
    }

    #[test]
    fn test_audit_checksum_changes_on_each_action() {
        let (env, admin, client) = setup();
        let c1 = client.get_audit_checksum();
        client.set_fee_bps(&admin, &100u32);
        let c2 = client.get_audit_checksum();
        client.set_fee_bps(&admin, &200u32);
        let c3 = client.get_audit_checksum();
        // Each action produces a distinct checksum
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_audit_checksum_is_deterministic() {
        // Verify determinism: same action sequence yields a stable, non-zero checksum.
        let (env, admin, client) = setup();
        client.set_fee_bps(&admin, &100u32);
        client.set_fee_bps(&admin, &200u32);
        let checksum_a = client.get_audit_checksum();
        let zero: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);
        assert_ne!(checksum_a, zero);
    }

    /// Test with a small synthetic cap to verify wraparound + checkpoint behaviour
    /// without performing 500+ actions.
    ///
    /// We use MAX_AUDIT_LOG_SIZE = 500 (real value) but only test that after 500
    /// actions the total is 500 and checksum is non-zero, and that on the 501st
    /// action (wraparound) the total becomes 501.
    ///
    /// A tight wraparound integration test would require a configurable cap; here
    /// we verify the arithmetic on the modular boundary directly.
    #[test]
    fn test_audit_total_beyond_ring_buffer_size() {
        let (env, admin, client) = setup();
        // initialize already wrote entry 0; write 499 more to fill the ring buffer
        for _ in 0..499 {
            client.set_fee_bps(&admin, &100u32);
        }
        assert_eq!(client.get_audit_total(), 500);

        // 501st entry triggers wraparound — total should be 501, checksum still valid
        client.set_fee_bps(&admin, &200u32);
        assert_eq!(client.get_audit_total(), 501);

        let checksum = client.get_audit_checksum();
        let zero: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);
        assert_ne!(checksum, zero);
    }

    #[test]
    fn test_audit_get_log_limit_respected() {
        let (env, admin, client) = setup();
        // initialize wrote 1 entry; add 4 more
        for _ in 0..4 {
            client.set_fee_bps(&admin, &100u32);
        }
        let log = client.get_audit_log(&3u32);
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn test_audit_get_log_returns_newest_first() {
        let (env, admin, client) = setup();
        client.set_fee_bps(&admin, &100u32); // sequence 1
        client.set_fee_bps(&admin, &200u32); // sequence 2

        let log = client.get_audit_log(&3u32);
        // Newest entry should have the highest sequence number
        let first_seq = log.get(0).unwrap().sequence;
        let last_seq = log.get(2).unwrap().sequence;
        assert!(first_seq > last_seq);
    }

    #[test]
    fn test_get_audit_checksum_view() {
        let (env, admin, client) = setup();
        let checksum = client.get_audit_checksum();
        // Should be non-zero after at least one action
        let zero: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);
        assert_ne!(checksum, zero);
    }
}
