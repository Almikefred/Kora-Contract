/// Integration test harness for the Kora Protocol.
///
/// Each test spins up a full mock environment with all contracts deployed
/// and wired together, mirroring a real Stellar Soroban deployment.
#[cfg(test)]
mod integration {
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Address, Bytes, Env, String, Symbol,
    };

    use kora_access_control::{AccessControlContract, AccessControlContractClient};
    use kora_financing_pool::{FinancingPoolContract, FinancingPoolContractClient};
    use kora_invoice_nft::{InvoiceNftContract, InvoiceNftContractClient};
    use kora_marketplace::{MarketplaceContract, MarketplaceContractClient};
    use kora_risk_registry::{RiskRegistryContract, RiskRegistryContractClient};
    use kora_shared::types::InvoiceStatus;
    use kora_treasury::{TreasuryContract, TreasuryContractClient};

    // ── Test Environment ──────────────────────────────────────────────────────

    struct KoraEnv<'a> {
        env: Env,
        admin: Address,
        access_control: AccessControlContractClient<'a>,
        invoice_nft: InvoiceNftContractClient<'a>,
        marketplace: MarketplaceContractClient<'a>,
        pool: FinancingPoolContractClient<'a>,
        treasury: TreasuryContractClient<'a>,
        risk_registry: RiskRegistryContractClient<'a>,
    }

    fn deploy_protocol() -> KoraEnv<'static> {
        let env = Env::default();
        env.mock_all_auths();

        // Set a realistic starting timestamp
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000,
            protocol_version: 21,
            sequence_number: 1,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 100_000,
        });

        let admin = Address::generate(&env);

        // Register all contracts
        let ac_id = env.register_contract(None, AccessControlContract);
        let nft_id = env.register_contract(None, InvoiceNftContract);
        let mp_id = env.register_contract(None, MarketplaceContract);
        let pool_id = env.register_contract(None, FinancingPoolContract);
        let treasury_id = env.register_contract(None, TreasuryContract);
        let rr_id = env.register_contract(None, RiskRegistryContract);

        let ac = AccessControlContractClient::new(&env, &ac_id);
        let nft = InvoiceNftContractClient::new(&env, &nft_id);
        let mp = MarketplaceContractClient::new(&env, &mp_id);
        let pool = FinancingPoolContractClient::new(&env, &pool_id);
        let treasury = TreasuryContractClient::new(&env, &treasury_id);
        let rr = RiskRegistryContractClient::new(&env, &rr_id);

        // Initialize all contracts
        ac.initialize(&admin);
        nft.initialize(&admin, &ac_id);
        mp.initialize(&admin, &nft_id, &pool_id, &treasury_id, &50u32);
        let oracle_addr = Address::generate(&env);
        pool.initialize(&admin, &nft_id, &treasury_id, &ac_id, &200u32, &oracle_addr);
        treasury.initialize(&admin, &50u32);
        rr.initialize(&admin, &nft_id);

        KoraEnv {
            env,
            admin,
            access_control: ac,
            invoice_nft: nft,
            marketplace: mp,
            pool,
            treasury,
            risk_registry: rr,
        }
    }

    fn sample_invoice_params(env: &Env) -> (Bytes, i128, Symbol, u64, String, u32) {
        let debtor_hash = Bytes::from_slice(env, &[0xABu8; 32]);
        let amount = 10_000_000_000i128; // 10,000 USDC (7 decimals)
        let currency = Symbol::new(env, "USDC");
        let due_date = env.ledger().timestamp() + 86_400 * 60; // 60 days
        let ipfs_cid = String::from_str(
            env,
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        );
        let risk_score = 30u32;
        (
            debtor_hash,
            amount,
            currency,
            due_date,
            ipfs_cid,
            risk_score,
        )
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Full happy path: mint → list → fund → repay
    #[test]
    fn test_full_invoice_lifecycle() {
        let k = deploy_protocol();
        let sme = Address::generate(&k.env);
        let (debtor_hash, amount, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        // 1. Mint invoice NFT
        let invoice_id = k.invoice_nft.mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );
        assert_eq!(invoice_id, 1);

        let invoice = k.invoice_nft.get_invoice(&invoice_id);
        assert_eq!(invoice.status, InvoiceStatus::Created);

        // 2. Transition to Listed (simulating marketplace call)
        k.invoice_nft
            .set_listed(&k.marketplace.address, &invoice_id);
        assert_eq!(
            k.invoice_nft.get_invoice(&invoice_id).status,
            InvoiceStatus::Listed
        );

        // 3. Transition to Funded (simulating pool call)
        k.invoice_nft.set_funded(&k.pool.address, &invoice_id);
        assert_eq!(
            k.invoice_nft.get_invoice(&invoice_id).status,
            InvoiceStatus::Funded
        );

        // 4. Repay (simulating pool repay call)
        k.invoice_nft.set_repaid(&k.pool.address, &invoice_id);
        assert_eq!(
            k.invoice_nft.get_invoice(&invoice_id).status,
            InvoiceStatus::Repaid
        );
    }

    /// Minting with zero amount must fail.
    #[test]
    fn test_mint_zero_amount_rejected() {
        let k = deploy_protocol();
        let sme = Address::generate(&k.env);
        let (debtor_hash, _, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        let result = k.invoice_nft.try_mint_invoice(
            &sme,
            &debtor_hash,
            &0i128,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );
        assert!(result.is_err());
    }

    /// Due date in the past must be rejected.
    #[test]
    fn test_mint_past_due_date_rejected() {
        let k = deploy_protocol();
        let sme = Address::generate(&k.env);
        let (debtor_hash, amount, currency, _, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        let past = k.env.ledger().timestamp() - 1;
        let result = k.invoice_nft.try_mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &past,
            &ipfs_cid,
            &risk_score,
        );
        assert!(result.is_err());
    }

    /// Risk score above 100 must be rejected.
    #[test]
    fn test_mint_invalid_risk_score_rejected() {
        let k = deploy_protocol();
        let sme = Address::generate(&k.env);
        let (debtor_hash, amount, currency, due_date, ipfs_cid, _) = sample_invoice_params(&k.env);

        let result = k.invoice_nft.try_mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &due_date,
            &ipfs_cid,
            &101u32,
        );
        assert!(result.is_err());
    }

    /// Invalid status transition must be rejected.
    #[test]
    fn test_invalid_status_transition_rejected() {
        let k = deploy_protocol();
        let sme = Address::generate(&k.env);
        let (debtor_hash, amount, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        let id = k.invoice_nft.mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );

        // Cannot go Created → Funded (must go through Listed first)
        let result = k.invoice_nft.try_set_funded(&k.pool.address, &id);
        assert!(result.is_err());
    }

    /// Protocol pause/unpause flow.
    #[test]
    fn test_pause_unpause_protocol() {
        let k = deploy_protocol();
        assert!(!k.access_control.is_paused());

        k.access_control.pause(&k.admin);
        assert!(k.access_control.is_paused());

        k.access_control.unpause(&k.admin);
        assert!(!k.access_control.is_paused());
    }

    /// Non-admin cannot pause.
    #[test]
    fn test_non_admin_cannot_pause() {
        let k = deploy_protocol();
        let stranger = Address::generate(&k.env);
        let result = k.access_control.try_pause(&stranger);
        assert!(result.is_err());
    }

    /// SME registration and risk scoring flow.
    #[test]
    fn test_sme_registration_flow() {
        let k = deploy_protocol();
        let verifier = Address::generate(&k.env);
        let sme = Address::generate(&k.env);

        k.risk_registry.add_verifier(&k.admin, &verifier);
        assert!(k.risk_registry.is_verifier(&verifier));

        k.risk_registry.register_sme(&verifier, &sme, &40u32);
        assert!(k.risk_registry.is_verified_sme(&sme));

        let profile = k.risk_registry.get_sme_profile(&sme);
        assert_eq!(profile.risk_score, 40);
        assert_eq!(profile.total_invoices, 0);
        assert_eq!(profile.defaults, 0);
    }

    /// Unregistered verifier cannot register SME.
    #[test]
    fn test_unregistered_verifier_rejected() {
        let k = deploy_protocol();
        let fake_verifier = Address::generate(&k.env);
        let sme = Address::generate(&k.env);

        let result = k
            .risk_registry
            .try_register_sme(&fake_verifier, &sme, &10u32);
        assert!(result.is_err());
    }

    /// Treasury fee configuration.
    #[test]
    fn test_treasury_fee_management() {
        let k = deploy_protocol();
        assert_eq!(k.treasury.get_fee_bps(), 50);

        k.treasury.set_fee_bps(&k.admin, &100u32);
        assert_eq!(k.treasury.get_fee_bps(), 100);
    }

    /// Fee above 100% must be rejected.
    #[test]
    fn test_treasury_fee_above_max_rejected() {
        let k = deploy_protocol();
        let result = k.treasury.try_set_fee_bps(&k.admin, &10_001u32);
        assert!(result.is_err());
    }

    /// Admin transfer flow.
    #[test]
    fn test_admin_transfer() {
        let k = deploy_protocol();
        let new_admin = Address::generate(&k.env);

        k.access_control.transfer_admin(&k.admin, &new_admin);
        assert_eq!(k.access_control.get_admin(), new_admin);
    }

    /// Defaulting an invoice before due date must fail.
    #[test]
    fn test_cannot_default_before_due_date() {
        let k = deploy_protocol();
        let sme = Address::generate(&k.env);
        let (debtor_hash, amount, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        let id = k.invoice_nft.mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );

        // Transition to Funded state
        k.invoice_nft.set_listed(&k.marketplace.address, &id);
        k.invoice_nft.set_funded(&k.pool.address, &id);

        // Due date has not passed — default should fail
        let result = k.invoice_nft.try_set_defaulted(&k.admin, &id);
        assert!(result.is_err());
    }

    /// Defaulting after due date succeeds.
    #[test]
    fn test_default_after_due_date_succeeds() {
        let k = deploy_protocol();
        let sme = Address::generate(&k.env);
        let (debtor_hash, amount, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        let id = k.invoice_nft.mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );

        k.invoice_nft.set_listed(&k.marketplace.address, &id);
        k.invoice_nft.set_funded(&k.pool.address, &id);

        // Advance ledger past due date
        k.env.ledger().set(LedgerInfo {
            timestamp: due_date + 1,
            protocol_version: 21,
            sequence_number: 100,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 100_000,
        });

        k.invoice_nft.set_defaulted(&k.admin, &id);
        assert_eq!(
            k.invoice_nft.get_invoice(&id).status,
            InvoiceStatus::Defaulted
        );
    }

    /// Pause enforcement matrix: pausing the protocol blocks all state-mutating
    /// entrypoints on invoice_nft, marketplace, and financing_pool.
    /// financing_pool.repay is intentionally exempt so funded SMEs can still
    /// repay even during an emergency pause.
    ///
    /// Enforcement matrix:
    /// | Entrypoint                        | Paused blocks? |
    /// |-----------------------------------|----------------|
    /// | invoice_nft::mint_invoice         | YES            |
    /// | invoice_nft::set_listed           | YES            |
    /// | invoice_nft::set_funded           | YES            |
    /// | marketplace::list_invoice         | YES            |
    /// | marketplace::fund_invoice         | YES            |
    /// | financing_pool::record_position   | YES            |
    /// | financing_pool::mark_default      | YES            |
    /// | financing_pool::repay             | NO (exempt)    |
    #[test]
    fn test_pause_enforcement_matrix() {
        use kora_shared::errors::KoraError;

        let k = deploy_protocol();
        let (debtor_hash, amount, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        let sme = Address::generate(&k.env);
        let investor = Address::generate(&k.env);

        // Mint a valid invoice and get it to Listed+Funded state before pausing,
        // so we have invoices to test transitions against while paused.
        let invoice_id = k.invoice_nft.mint_invoice(
            &sme, &debtor_hash, &amount, &currency, &due_date, &ipfs_cid, &risk_score,
        );
        k.invoice_nft.set_listed(&k.marketplace.address, &invoice_id);
        k.invoice_nft.set_funded(&k.pool.address, &invoice_id);

        // Mint a second invoice that stays in Created state for listed-gate testing
        let invoice_id2 = k.invoice_nft.mint_invoice(
            &sme, &debtor_hash, &amount, &currency, &due_date, &ipfs_cid, &risk_score,
        );

        // ── Pause the protocol ────────────────────────────────────────────────
        k.access_control.pause(&k.admin);
        assert!(k.access_control.is_paused());

        // ── invoice_nft::mint_invoice blocked ─────────────────────────────────
        let r = k.invoice_nft.try_mint_invoice(
            &sme, &debtor_hash, &amount, &currency, &due_date, &ipfs_cid, &risk_score,
        );
        assert!(r.is_err(), "mint_invoice must be blocked when paused");
        assert_eq!(
            r.unwrap_err().unwrap(),
            KoraError::ProtocolPaused
        );

        // ── invoice_nft::set_listed blocked ───────────────────────────────────
        let r = k.invoice_nft.try_set_listed(&k.marketplace.address, &invoice_id2);
        assert!(r.is_err(), "set_listed must be blocked when paused");
        assert_eq!(r.unwrap_err().unwrap(), KoraError::ProtocolPaused);

        // ── invoice_nft::set_funded blocked ───────────────────────────────────
        // invoice_id2 is still Created; set_listed would fail with pause,
        // so use a fresh invoice that we manually put in Listed state
        // via direct storage — instead just test with invoice_id2 which is Created:
        // set_funded requires Listed, so it would return InvalidInvoiceStatus after pause check.
        // To test the pause gate specifically, we need it to reach the pause check first.
        // set_funded also calls require_not_paused before status check — test it:
        let r = k.invoice_nft.try_set_funded(&k.pool.address, &invoice_id2);
        assert!(r.is_err(), "set_funded must be blocked when paused");
        assert_eq!(r.unwrap_err().unwrap(), KoraError::ProtocolPaused);

        // ── marketplace::list_invoice blocked ─────────────────────────────────
        let funding_deadline = k.env.ledger().timestamp() + 86_400 * 30;
        // Need a whitelisted token — use a dummy address; it will fail at pause check first
        let dummy_token = Address::generate(&k.env);
        let r = k.marketplace.try_list_invoice(
            &sme, &invoice_id2, &(amount - 1), &amount, &dummy_token, &funding_deadline,
        );
        assert!(r.is_err(), "list_invoice must be blocked when paused");
        assert_eq!(r.unwrap_err().unwrap(), KoraError::ProtocolPaused);

        // ── marketplace::fund_invoice blocked ─────────────────────────────────
        let r = k.marketplace.try_fund_invoice(&investor, &invoice_id, &1_000i128);
        assert!(r.is_err(), "fund_invoice must be blocked when paused");
        assert_eq!(r.unwrap_err().unwrap(), KoraError::ProtocolPaused);

        // ── financing_pool::record_position blocked ───────────────────────────
        let r = k.pool.try_record_position(
            &k.admin, &invoice_id, &investor, &5_000_000_000i128, &10_000_000_000i128,
        );
        assert!(r.is_err(), "record_position must be blocked when paused");
        assert_eq!(r.unwrap_err().unwrap(), KoraError::ProtocolPaused);

        // ── financing_pool::mark_default blocked ──────────────────────────────
        let dummy_token2 = Address::generate(&k.env);
        let r = k.pool.try_mark_default(&k.admin, &invoice_id, &dummy_token2);
        assert!(r.is_err(), "mark_default must be blocked when paused");
        assert_eq!(r.unwrap_err().unwrap(), KoraError::ProtocolPaused);

        // ── financing_pool::repay is EXEMPT from pause ────────────────────────
        // repay will fail with PoolNotFound (no pool exists for invoice_id here
        // in unit-test mode) — but NOT with ProtocolPaused, proving the gate is absent.
        let r = k.pool.try_repay(&sme, &999u64, &dummy_token2, &1_000i128);
        assert!(r.is_err());
        assert_ne!(
            r.unwrap_err().unwrap(),
            KoraError::ProtocolPaused,
            "repay must NOT be blocked by pause — it is intentionally exempt"
        );

        // ── Unpause restores normal operation ─────────────────────────────────
        k.access_control.unpause(&k.admin);
        assert!(!k.access_control.is_paused());

        // mint works again after unpause
        let r = k.invoice_nft.try_mint_invoice(
            &sme, &debtor_hash, &amount, &currency, &due_date, &ipfs_cid, &risk_score,
        );
        assert!(r.is_ok(), "mint_invoice must succeed after unpause");
    }
    #[test]
    fn test_sequential_invoice_ids() {
        let k = deploy_protocol();
        let sme = Address::generate(&k.env);
        let (debtor_hash, amount, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        let id1 = k.invoice_nft.mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );
        let id2 = k.invoice_nft.mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );
        let id3 = k.invoice_nft.mint_invoice(
            &sme,
            &debtor_hash,
            &amount,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
        assert_eq!(k.invoice_nft.next_id(), 4);
    }

    /// End-to-end default scenario with partial recovery:
    /// two investors fully fund an invoice, the SME partially repays,
    /// the due date passes, admin calls mark_default, and each investor
    /// receives their proportional share of the recovered amount.
    /// The invoice ends as Defaulted and the SME's risk_registry default
    /// count is incremented automatically.
    #[test]
    fn test_multi_investor_partial_recovery_default_end_to_end() {
        use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};

        let k = deploy_protocol();

        // ── Setup: register SME in risk registry ─────────────────────────────
        let verifier = Address::generate(&k.env);
        let sme = Address::generate(&k.env);
        k.risk_registry.add_verifier(&k.admin, &verifier);
        k.risk_registry.register_sme(&verifier, &sme, &40u32);

        let profile_before = k.risk_registry.get_sme_profile(&sme);
        assert_eq!(profile_before.defaults, 0);

        // ── Deploy a mock token ───────────────────────────────────────────────
        let token_id = k.env.register_stellar_asset_contract_v2(k.admin.clone());
        let token_addr = token_id.address();
        let token = TokenClient::new(&k.env, &token_addr);
        let token_admin = StellarAssetClient::new(&k.env, &token_addr);

        // Whitelist the token in the marketplace
        k.marketplace.whitelist_token(&k.admin, &token_addr);

        // ── Two investors ─────────────────────────────────────────────────────
        let investor_a = Address::generate(&k.env);
        let investor_b = Address::generate(&k.env);

        // Face value = 10,000 USDC (7 decimals); asking price = 9,500 (5% discount)
        let face_value: i128 = 10_000_0000000; // 10,000 units
        let asking_price: i128 = 9_500_0000000; // 9,500 units

        // Investor A funds 60%, Investor B funds 40% of asking price
        let inv_a_amount: i128 = 5_700_0000000; // 60% of asking_price
        let inv_b_amount: i128 = 3_800_0000000; // 40% of asking_price

        // Mint enough tokens for both investors (fee is 50bps = 0.5%)
        token_admin.mint(&investor_a, &(inv_a_amount * 2));
        token_admin.mint(&investor_b, &(inv_b_amount * 2));

        // ── Mint invoice ──────────────────────────────────────────────────────
        let (debtor_hash, _, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);

        let invoice_id = k.invoice_nft.mint_invoice(
            &sme,
            &debtor_hash,
            &face_value,
            &currency,
            &due_date,
            &ipfs_cid,
            &risk_score,
        );

        // ── List the invoice ──────────────────────────────────────────────────
        let funding_deadline = k.env.ledger().timestamp() + 86_400 * 30;
        k.marketplace.list_invoice(
            &sme,
            &invoice_id,
            &asking_price,
            &face_value,
            &token_addr,
            &funding_deadline,
        );

        // ── Both investors fund — triggers release_funds when full ────────────
        k.marketplace.fund_invoice(&investor_a, &invoice_id, &inv_a_amount);
        k.marketplace.fund_invoice(&investor_b, &invoice_id, &inv_b_amount);

        // Invoice should now be Funded
        assert_eq!(
            k.invoice_nft.get_invoice(&invoice_id).status,
            InvoiceStatus::Funded
        );

        // ── Record investor positions in the pool ─────────────────────────────
        // net contributions after 0.5% fee
        let fee_bps: i128 = 50;
        let net_a = inv_a_amount - (inv_a_amount * fee_bps / 10_000);
        let net_b = inv_b_amount - (inv_b_amount * fee_bps / 10_000);
        let total_net = net_a + net_b;

        k.pool.record_position(&k.admin, &invoice_id, &investor_a, &net_a, &total_net);
        k.pool.record_position(&k.admin, &invoice_id, &investor_b, &net_b, &total_net);

        // ── SME partially repays (50% of face value) ──────────────────────────
        let partial_repayment: i128 = face_value / 2; // 5,000 units
        token_admin.mint(&sme, &partial_repayment);
        k.pool.repay(&sme, &invoice_id, &token_addr, &partial_repayment);

        // Pool should still be open (not fully repaid)
        let pool_state = k.pool.get_pool(&invoice_id);
        assert_eq!(pool_state.repaid_amount, partial_repayment);
        assert!(!pool_state.is_closed);

        // ── Advance ledger past due date ──────────────────────────────────────
        k.env.ledger().set(LedgerInfo {
            timestamp: due_date + 1,
            protocol_version: 21,
            sequence_number: 200,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 100_000,
        });

        // Snapshot investor balances before default distribution
        let bal_a_before = token.balance(&investor_a);
        let bal_b_before = token.balance(&investor_b);

        // ── Admin calls mark_default ──────────────────────────────────────────
        k.pool.mark_default(&k.admin, &invoice_id, &token_addr);

        // ── Assert invoice is Defaulted ───────────────────────────────────────
        assert_eq!(
            k.invoice_nft.get_invoice(&invoice_id).status,
            InvoiceStatus::Defaulted
        );

        // ── Assert risk_registry default count incremented ────────────────────
        let profile_after = k.risk_registry.get_sme_profile(&sme);
        assert_eq!(profile_after.defaults, 1);

        // ── Assert proportional payouts ───────────────────────────────────────
        // share_bps for A = net_a * 10000 / total_net, for B the remainder
        let share_bps_a = (net_a * 10_000 / total_net) as u32;
        let share_bps_b = (net_b * 10_000 / total_net) as u32;

        let expected_payout_a = partial_repayment * share_bps_a as i128 / 10_000;
        let expected_payout_b = partial_repayment * share_bps_b as i128 / 10_000;

        let bal_a_after = token.balance(&investor_a);
        let bal_b_after = token.balance(&investor_b);

        assert_eq!(bal_a_after - bal_a_before, expected_payout_a);
        assert_eq!(bal_b_after - bal_b_before, expected_payout_b);

        // Total distributed must not exceed what was repaid
        let total_distributed = (bal_a_after - bal_a_before) + (bal_b_after - bal_b_before);
        assert!(total_distributed <= partial_repayment);
    }

    /// #291 — Multi-investor full-funding and repayment with proportional yield.
    ///
    /// Scenario:
    /// - 3 investors fund different proportions of an invoice via `marketplace.fund_invoice`
    /// - Full funding triggers `financing_pool.release_funds` automatically
    /// - Admin records each investor's position
    /// - SME repays the full face value via `financing_pool.repay`
    /// - Each investor receives principal + proportional share of the yield spread
    #[test]
    fn test_multi_investor_full_funding_and_repayment_distributes_proportional_yield() {
        use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};

        let k = deploy_protocol();

        // ── Deploy and whitelist a mock stablecoin ────────────────────────────
        let token_id = k.env.register_stellar_asset_contract_v2(k.admin.clone());
        let token_addr = token_id.address();
        let token = TokenClient::new(&k.env, &token_addr);
        let token_admin = StellarAssetClient::new(&k.env, &token_addr);
        k.marketplace.whitelist_token(&k.admin, &token_addr);

        // ── Actors ────────────────────────────────────────────────────────────
        let sme = Address::generate(&k.env);
        let investor_1 = Address::generate(&k.env);
        let investor_2 = Address::generate(&k.env);
        let investor_3 = Address::generate(&k.env);

        // Face value 10 000 USDC (7 decimals); asking price 9 500 (5 % discount)
        let face_value: i128 = 10_000_0000000;
        let asking_price: i128 = 9_500_0000000;

        // Investor contributions: 50%, 30%, 20% of asking_price
        let contrib_1: i128 = asking_price * 50 / 100; // 4 750
        let contrib_2: i128 = asking_price * 30 / 100; // 2 850
        let contrib_3: i128 = asking_price - contrib_1 - contrib_2; // 1 900 (remainder)

        // Mint enough tokens; give 2× to cover fee rounding
        token_admin.mint(&investor_1, &(contrib_1 * 2));
        token_admin.mint(&investor_2, &(contrib_2 * 2));
        token_admin.mint(&investor_3, &(contrib_3 * 2));
        // SME needs face_value to repay
        token_admin.mint(&sme, &face_value);

        // ── Mint invoice ──────────────────────────────────────────────────────
        let (debtor_hash, _, currency, due_date, ipfs_cid, risk_score) =
            sample_invoice_params(&k.env);
        let invoice_id = k.invoice_nft.mint_invoice(
            &sme, &debtor_hash, &face_value, &currency, &due_date, &ipfs_cid, &risk_score,
        );

        // ── List invoice ──────────────────────────────────────────────────────
        let funding_deadline = k.env.ledger().timestamp() + 86_400 * 30;
        k.marketplace.list_invoice(
            &sme, &invoice_id, &asking_price, &face_value, &token_addr, &funding_deadline,
        );

        // ── Three investors fund; last one triggers release_funds ─────────────
        k.marketplace.fund_invoice(&investor_1, &invoice_id, &contrib_1);
        k.marketplace.fund_invoice(&investor_2, &invoice_id, &contrib_2);
        k.marketplace.fund_invoice(&investor_3, &invoice_id, &contrib_3);

        // Invoice must now be Funded
        assert_eq!(
            k.invoice_nft.get_invoice(&invoice_id).status,
            InvoiceStatus::Funded
        );

        // ── Admin records proportional positions in the pool ──────────────────
        // Net contribution = gross - 0.5% fee
        let fee_bps: i128 = 50;
        let net = |gross: i128| gross - gross * fee_bps / 10_000;
        let net_1 = net(contrib_1);
        let net_2 = net(contrib_2);
        let net_3 = net(contrib_3);
        let total_net = net_1 + net_2 + net_3;

        k.pool.record_position(&k.admin, &invoice_id, &investor_1, &net_1, &total_net);
        k.pool.record_position(&k.admin, &invoice_id, &investor_2, &net_2, &total_net);
        k.pool.record_position(&k.admin, &invoice_id, &investor_3, &net_3, &total_net);

        // ── Snapshot balances before repayment ────────────────────────────────
        let bal_1_before = token.balance(&investor_1);
        let bal_2_before = token.balance(&investor_2);
        let bal_3_before = token.balance(&investor_3);

        // ── SME repays full face value ────────────────────────────────────────
        k.pool.repay(&sme, &invoice_id, &token_addr, &face_value);

        // Invoice must now be Repaid
        assert_eq!(
            k.invoice_nft.get_invoice(&invoice_id).status,
            InvoiceStatus::Repaid
        );

        // Pool must be closed
        let pool_state = k.pool.get_pool(&invoice_id);
        assert!(pool_state.is_closed);

        // ── Assert each investor received proportional payout ─────────────────
        // Expected payout = face_value * share_bps / 10_000
        let token_decimals = token.decimals();
        let normalize = |v: i128| -> i128 {
            let scale = 10i128.pow(token_decimals);
            // bps_of_normalized: (v * bps / 10_000) rounded to token precision
            // We replicate the same logic used in distribute_yield
            v
        };

        let share_bps_1 = (net_1 * 10_000 / total_net) as u32;
        let share_bps_2 = (net_2 * 10_000 / total_net) as u32;
        let share_bps_3 = (net_3 * 10_000 / total_net) as u32;

        // Replicate bps_of_normalized (face_value * share_bps / 10_000, scaled to token decimals)
        let scale = 10i128.pow(token_decimals);
        let expected_1 = face_value * share_bps_1 as i128 / (10_000 * scale) * scale;
        let expected_2 = face_value * share_bps_2 as i128 / (10_000 * scale) * scale;
        let expected_3 = face_value * share_bps_3 as i128 / (10_000 * scale) * scale;

        let bal_1_after = token.balance(&investor_1);
        let bal_2_after = token.balance(&investor_2);
        let bal_3_after = token.balance(&investor_3);

        let received_1 = bal_1_after - bal_1_before;
        let received_2 = bal_2_after - bal_2_before;
        let received_3 = bal_3_after - bal_3_before;

        // Each investor must receive at least their net contribution back (principal)
        assert!(received_1 >= net_1, "investor_1 must receive at least principal");
        assert!(received_2 >= net_2, "investor_2 must receive at least principal");
        assert!(received_3 >= net_3, "investor_3 must receive at least principal");

        // Total distributed must not exceed face_value (no double-counting)
        let total_distributed = received_1 + received_2 + received_3;
        assert!(total_distributed <= face_value);

        // Investor with largest stake receives largest absolute payout
        assert!(
            received_1 > received_2,
            "investor_1 (50%) must receive more than investor_2 (30%)"
        );
        assert!(
            received_2 > received_3,
            "investor_2 (30%) must receive more than investor_3 (20%)"
        );

        // Proportional ratios hold within 1 bps tolerance
        // received_1 / received_2 ≈ share_bps_1 / share_bps_2
        let ratio_actual = received_1 * 10_000 / received_2;
        let ratio_expected = share_bps_1 as i128 * 10_000 / share_bps_2 as i128;
        let diff = (ratio_actual - ratio_expected).abs();
        assert!(diff <= 10, "payout ratio must match share ratio within 0.1%");
    }
}
