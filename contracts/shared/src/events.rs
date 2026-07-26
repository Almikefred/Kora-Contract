use soroban_sdk::{symbol_short, Address, Env, Symbol};

fn emit(env: &Env, name: Symbol, data: impl soroban_sdk::IntoVal<Env, soroban_sdk::Val>) {
    env.events().publish((name,), data);
}

// ── Invoice Events ──────────────────────────────────────────────────────────

pub fn invoice_created(env: &Env, invoice_id: u64, sme: &Address, amount: i128) {
    emit(
        env,
        symbol_short!("INV_CRT"),
        (invoice_id, sme.clone(), amount),
    );
}

pub fn invoice_listed(env: &Env, invoice_id: u64, seller: &Address, asking_price: i128) {
    emit(
        env,
        symbol_short!("INV_LST"),
        (invoice_id, seller.clone(), asking_price),
    );
}

pub fn invoice_funded(env: &Env, invoice_id: u64, investor: &Address, amount: i128) {
    emit(
        env,
        symbol_short!("INV_FND"),
        (invoice_id, investor.clone(), amount),
    );
}

pub fn invoice_repaid(env: &Env, invoice_id: u64, sme: &Address, amount: i128) {
    emit(env, symbol_short!("INV_RPD"), (invoice_id, sme.clone(), amount));
}

pub fn invoice_defaulted(env: &Env, invoice_id: u64, sme: &Address) {
    emit(env, symbol_short!("INV_DFT"), (invoice_id, sme.clone()));
}

// ── Repayment Events ────────────────────────────────────────────────────────

pub fn repayment_made(env: &Env, invoice_id: u64, payer: &Address, amount: i128) {
    emit(
        env,
        symbol_short!("REPAY"),
        (invoice_id, payer.clone(), amount),
    );
}

pub fn yield_distributed(env: &Env, invoice_id: u64, investor: &Address, yield_amount: i128) {
    emit(
        env,
        symbol_short!("YIELD"),
        (invoice_id, investor.clone(), yield_amount),
    );
}

// ── Marketplace Events ──────────────────────────────────────────────────────

// ── Marketplace Events ────────────────────────────────────────────────────────

pub fn listing_cancelled(env: &Env, invoice_id: u64, seller: &Address) {
    emit(env, symbol_short!("LST_CXL"), (invoice_id, seller.clone(), env.ledger().timestamp()));
}

pub fn listing_expired(env: &Env, invoice_id: u64, seller: &Address) {
    emit(env, symbol_short!("LST_EXP"), (invoice_id, seller.clone(), env.ledger().timestamp()));
}

// ── Fee Events ────────────────────────────────────────────────────────────────

pub fn fee_collected(env: &Env, invoice_id: u64, fee_amount: i128, token: &Address) {
    emit(
        env,
        symbol_short!("FEE_COL"),
        (invoice_id, fee_amount, token.clone()),
    );
}

// ── Protocol Events ────────────────────────────────────────────────────────

pub fn protocol_paused(env: &Env, by: &Address) {
    emit(env, symbol_short!("PAUSED"), (by.clone(), env.ledger().timestamp()));
}

pub fn protocol_unpaused(env: &Env, by: &Address) {
    emit(env, symbol_short!("UNPAUSED"), (by.clone(), env.ledger().timestamp()));
}

pub fn fee_withdrawn(env: &Env, token: &Address, amount: i128) {
    emit(env, symbol_short!("FEE_WTH"), (token.clone(), amount));
}

pub fn admin_transferred(env: &Env, new_admin: &Address) {
    emit(env, symbol_short!("ADM_TRF"), new_admin.clone());
}

// ── Audit Events ─────────────────────────────────────────────────────────────

/// Emitted on every admin action — canonical off-chain history source.
pub fn adm_audit(env: &Env, sequence: u64, action: soroban_sdk::String, actor: &Address, timestamp: u64) {
    emit(
        env,
        symbol_short!("ADM_AUDT"),
        (sequence, action, actor.clone(), timestamp),
    );
}

/// Emitted right before a ring-buffer wraparound begins overwriting old entries.
/// Carries the rolling checksum that commits the full history up to this point,
/// and the raw entry that is about to be discarded — giving off-chain systems an
/// unambiguous, permanent archival signal.
pub fn audit_checkpoint(
    env: &Env,
    total_entries: u64,
    checksum: soroban_sdk::BytesN<32>,
    discarded_action: soroban_sdk::String,
    discarded_actor: &Address,
    discarded_timestamp: u64,
    discarded_sequence: u64,
) {
    emit(
        env,
        symbol_short!("AUDT_CHK"),
        (
            total_entries,
            checksum,
            discarded_action,
            discarded_actor.clone(),
            discarded_timestamp,
            discarded_sequence,
        ),
    );
}
