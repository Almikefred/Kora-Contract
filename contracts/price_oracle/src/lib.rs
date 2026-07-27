#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol};

const MAX_STALENESS_SECS: u64 = 3600;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PriceOracleError {
    AlreadyInitialized = 1,
    ArithmeticOverflow = 2,
    InvalidAmount = 3,
    InvoiceExpired = 4,
    NotAdmin = 5,
    NotInitialized = 6,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PriceData {
    pub price: i128,
    pub timestamp: u64,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Price(Symbol, Symbol),
}

#[contract]
pub struct PriceOracleContract;

#[contractimpl]
impl PriceOracleContract {
    pub fn initialize(env: Env, admin: Address) -> Result<(), PriceOracleError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(PriceOracleError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Set a price for a currency pair. Admin only.
    /// Price is expressed as `base` units per 1 unit of `quote`, scaled by 1e7 (stroops).
    /// If the reverse pair (quote, base) is already set, validates that the prices are
    /// reciprocal-consistent within tolerance (allowing for rounding; exact match is not required).
    pub fn set_price(
        env: Env,
        admin: Address,
        base: Symbol,
        quote: Symbol,
        price: i128,
    ) -> Result<(), PriceOracleError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;

        if price <= 0 {
            return Err(PriceOracleError::InvalidAmount);
        }

        // Check reciprocal consistency if reverse pair exists
        if let Ok(reverse_data) = Self::get_price(env.clone(), quote.clone(), base.clone()) {
            // Expected reciprocal: if P is forward price, reverse should be ~10^14 / P
            // We compute the reciprocal and allow 1% tolerance for rounding
            let expected_reciprocal = Self::compute_reciprocal(price)?;
            let tolerance_bps = 100; // 1% = 100 basis points
            Self::validate_reciprocal_tolerance(expected_reciprocal, reverse_data.price, tolerance_bps)?;
        }

        let data = PriceData {
            price,
            timestamp: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::Price(base, quote), &data);
        Ok(())
    }

    /// Compute the mathematical reciprocal of a price: 10^14 / price
    /// The 10^14 accounts for the 1e7 scaling on both sides.
    fn compute_reciprocal(price: i128) -> Result<i128, PriceOracleError> {
        if price <= 0 {
            return Err(PriceOracleError::InvalidAmount);
        }
        (100_000_000_000_000i128)
            .checked_div(price)
            .ok_or(PriceOracleError::ArithmeticOverflow)
    }

    /// Validate that two prices are reciprocally consistent within a tolerance (in basis points).
    /// tolerance_bps: e.g., 100 = 1%, 10 = 0.1%
    fn validate_reciprocal_tolerance(
        expected: i128,
        actual: i128,
        tolerance_bps: u32,
    ) -> Result<(), PriceOracleError> {
        if expected <= 0 || actual <= 0 {
            return Err(PriceOracleError::InvalidAmount);
        }
        // Compute percentage difference: |expected - actual| / expected * 10000
        let diff = if expected > actual {
            expected.checked_sub(actual).ok_or(PriceOracleError::ArithmeticOverflow)?
        } else {
            actual.checked_sub(expected).ok_or(PriceOracleError::ArithmeticOverflow)?
        };
        let pct_diff_bps = diff
            .checked_mul(10000)
            .and_then(|v| v.checked_div(expected))
            .ok_or(PriceOracleError::ArithmeticOverflow)?;

        if pct_diff_bps > tolerance_bps as i128 {
            return Err(PriceOracleError::InvalidAmount);
        }
        Ok(())
    }

    /// Get the price for a pair. Returns the price and its timestamp.
    /// Fails if the price is stale (older than MAX_STALENESS_SECS) or missing.
    pub fn get_price(
        env: Env,
        base: Symbol,
        quote: Symbol,
    ) -> Result<PriceData, PriceOracleError> {
        let data: PriceData = env
            .storage()
            .persistent()
            .get(&DataKey::Price(base.clone(), quote.clone()))
            .ok_or(PriceOracleError::InvalidAmount)?;

        let age = env
            .ledger()
            .timestamp()
            .saturating_sub(data.timestamp);
        if age > MAX_STALENESS_SECS {
            return Err(PriceOracleError::InvoiceExpired);
        }

        Ok(data)
    }

    /// Convert an amount from one currency to another using the stored price.
    /// Rejects stale or missing prices.
    /// Does not adjust for token decimal differences; prices must account for decimals.
    pub fn convert(
        env: Env,
        amount: i128,
        from: Symbol,
        to: Symbol,
    ) -> Result<i128, PriceOracleError> {
        if from == to {
            return Ok(amount);
        }

        let price_data = Self::get_price(env.clone(), from, to)?;
        let converted = amount
            .checked_mul(price_data.price)
            .and_then(|v| v.checked_div(10_000_000))
            .ok_or(PriceOracleError::ArithmeticOverflow)?;

        if converted <= 0 {
            return Err(PriceOracleError::InvalidAmount);
        }

        Ok(converted)
    }

    /// Convert an amount between currencies with decimal precision correction.
    /// Applies: amount_out = (amount_in * price_ratio / 1e7) * 10^(to_decimals - from_decimals)
    /// This corrects for differing token decimal places (e.g., 6 vs 7 decimal tokens).
    ///
    /// **Parameters:**
    /// - `amount` — The input amount in `from` currency's smallest unit.
    /// - `from` — Source currency symbol.
    /// - `to` — Target currency symbol.
    /// - `from_decimals` — Decimal places of the `from` token (typically 6 or 7).
    /// - `to_decimals` — Decimal places of the `to` token (typically 6 or 7).
    ///
    /// **Returns:** Converted amount in `to` currency's smallest unit.
    ///
    /// **Errors:**
    /// - `PriceOracleError::ArithmeticOverflow` — Multiplication or division overflowed.
    /// - `PriceOracleError::InvalidAmount` — Price not found, stale, or result is ≤ 0.
    /// - `PriceOracleError::InvoiceExpired` — Price data is older than MAX_STALENESS_SECS.
    pub fn convert_with_decimals(
        env: Env,
        amount: i128,
        from: Symbol,
        to: Symbol,
        from_decimals: u32,
        to_decimals: u32,
    ) -> Result<i128, PriceOracleError> {
        if from == to {
            return Ok(amount);
        }

        let price_data = Self::get_price(env.clone(), from.clone(), to.clone())?;
        // First: apply price ratio scaled by 1e7
        let converted = amount
            .checked_mul(price_data.price)
            .and_then(|v| v.checked_div(10_000_000))
            .ok_or(PriceOracleError::ArithmeticOverflow)?;

        if converted <= 0 {
            return Err(PriceOracleError::InvalidAmount);
        }

        // Second: apply decimal rescaling based on token precision differences
        let rescaled = if from_decimals >= to_decimals {
            let divisor = Self::compute_10_pow(from_decimals - to_decimals)?;
            converted
                .checked_div(divisor)
                .ok_or(PriceOracleError::ArithmeticOverflow)?
        } else {
            let multiplier = Self::compute_10_pow(to_decimals - from_decimals)?;
            converted
                .checked_mul(multiplier)
                .ok_or(PriceOracleError::ArithmeticOverflow)?
        };

        if rescaled <= 0 {
            return Err(PriceOracleError::InvalidAmount);
        }

        Ok(rescaled)
    }

    fn compute_10_pow(exp: u32) -> Result<i128, PriceOracleError> {
        match exp {
            0 => Ok(1),
            1 => Ok(10),
            2 => Ok(100),
            3 => Ok(1_000),
            4 => Ok(10_000),
            5 => Ok(100_000),
            6 => Ok(1_000_000),
            7 => Ok(10_000_000),
            8 => Ok(100_000_000),
            9 => Ok(1_000_000_000),
            10 => Ok(10_000_000_000),
            _ => Err(PriceOracleError::ArithmeticOverflow),
        }
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), PriceOracleError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(PriceOracleError::NotInitialized)?;
        if &admin != caller {
            return Err(PriceOracleError::NotAdmin);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env, Symbol};

    fn setup() -> (Env, Address, PriceOracleContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PriceOracleContract);
        let client = PriceOracleContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_set_and_get_price() {
        let (env, admin, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");
        client.set_price(&admin, &base, &quote, &11_000_000i128);
        let data = client.get_price(&base, &quote);
        assert_eq!(data.price, 11_000_000i128);
    }

    #[test]
    fn test_convert_same_currency() {
        let (env, _admin, client) = setup();
        let sym = Symbol::new(&env, "USDC");
        let result = client.convert(&1_000_000i128, &sym, &sym);
        assert_eq!(result, 1_000_000i128);
    }

    #[test]
    fn test_convert_different_currency() {
        let (env, admin, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let usdc = Symbol::new(&env, "USDC");
        // 1 EURC = 1.1 USDC (11_000_000 stroops per 10_000_000)
        client.set_price(&admin, &eurc, &usdc, &11_000_000i128);
        let result = client.convert(&10_000_000i128, &eurc, &usdc);
        assert_eq!(result, 11_000_000i128);
    }

    #[test]
    fn test_get_price_missing_fails() {
        let (env, _admin, client) = setup();
        let base = Symbol::new(&env, "XLM");
        let quote = Symbol::new(&env, "USDC");
        let result = client.try_get_price(&base, &quote);
        assert!(result.is_err());
    }

    #[test]
    fn test_stale_price_rejected() {
        use soroban_sdk::testutils::{Ledger, LedgerInfo};
        let (env, admin, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");
        client.set_price(&admin, &base, &quote, &11_000_000i128);

        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + MAX_STALENESS_SECS + 1,
            protocol_version: 21,
            sequence_number: 2,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 100_000,
        });

        let result = client.try_get_price(&base, &quote);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_with_decimals_same_decimals() {
        let (env, admin, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let usdc = Symbol::new(&env, "USDC");
        // 1 EURC = 1.1 USDC (11_000_000 stroops per 10_000_000)
        client.set_price(&admin, &eurc, &usdc, &11_000_000i128);
        // Both have 7 decimals: no rescaling needed, should match convert()
        let result = client.convert_with_decimals(&10_000_000i128, &eurc, &usdc, &7u32, &7u32);
        assert_eq!(result, 11_000_000i128);
    }

    #[test]
    fn test_convert_with_decimals_from_7_to_6() {
        let (env, admin, client) = setup();
        let token7 = Symbol::new(&env, "TOK7");
        let token6 = Symbol::new(&env, "TOK6");
        // Price: 1 TOK7 unit = 1.1 TOK6 units (scaled at 1e7)
        client.set_price(&admin, &token7, &token6, &11_000_000i128);
        // Input: 10_000_000 units of 7-decimal token
        // Expected (raw): 11_000_000 units of 6-decimal token
        // But we rescale by dividing by 10 (7-6=1): 11_000_000 / 10 = 1_100_000
        let result = client.convert_with_decimals(&10_000_000i128, &token7, &token6, &7u32, &6u32);
        assert_eq!(result, 1_100_000i128);
    }

    #[test]
    fn test_convert_with_decimals_from_6_to_7() {
        let (env, admin, client) = setup();
        let token6 = Symbol::new(&env, "TOK6");
        let token7 = Symbol::new(&env, "TOK7");
        // Price: 1 TOK6 unit = 0.9090... TOK7 units (scaled); use 9_090_909 ~ 1e7 / 1.1
        client.set_price(&admin, &token6, &token7, &9_090_909i128);
        // Input: 1_000_000 units of 6-decimal token
        // Expected (raw): 9_090_909 units of 7-decimal token
        // But we rescale by multiplying by 10 (7-6=1): 9_090_909 * 10 = 90_909_090
        let result = client.convert_with_decimals(&1_000_000i128, &token6, &token7, &6u32, &7u32);
        assert_eq!(result, 90_909_090i128);
    }

    #[test]
    fn test_convert_with_decimals_regression_old_math_wrong() {
        let (env, admin, client) = setup();
        let token7 = Symbol::new(&env, "TOK7");
        let token6 = Symbol::new(&env, "TOK6");
        // If old convert() were used without decimals for 7→6: it would be off by 10x
        client.set_price(&admin, &token7, &token6, &11_000_000i128);

        // Old convert() for 10_000_000 units would give 11_000_000 (wrong order of magnitude)
        // New convert_with_decimals gives 1_100_000 (correct after rescaling)
        let old_result = client.convert(&10_000_000i128, &token7, &token6);
        let new_result = client.convert_with_decimals(&10_000_000i128, &token7, &token6, &7u32, &6u32);

        assert_eq!(old_result, 11_000_000i128, "old convert gives raw price-adjusted value");
        assert_eq!(new_result, 1_100_000i128, "new convert_with_decimals correctly rescales");
        assert_eq!(old_result, new_result * 10, "old result is exactly 10x the correct result");
    }

    #[test]
    fn test_convert_with_decimals_round_trip() {
        let (env, admin, client) = setup();
        let usdc = Symbol::new(&env, "USDC");
        let eurc = Symbol::new(&env, "EURC");
        // USDC: 6 decimals, EURC: 7 decimals
        // Forward: 1 USDC = 0.9 EURC (at 1e7 scale)
        client.set_price(&admin, &usdc, &eurc, &9_000_000i128);
        // Reverse: 1 EURC ≈ 1.111... USDC (at 1e7 scale ≈ 1_111_111)
        client.set_price(&admin, &eurc, &usdc, &11_111_111i128);

        let start = 1_000_000i128; // 1 USDC
        let to_eurc = client.convert_with_decimals(&start, &usdc, &eurc, &6u32, &7u32).unwrap();
        // start (1M) * 9_000_000 / 1e7 * 10 = 1M * 9 / 10 * 10 = 9M
        // Actually: (1_000_000 * 9_000_000) / 1e7 * 10 = 9_000_000_000_000 / 1e7 * 10 = 900 * 10 = 9_000

        // Let's verify with actual math:
        // 1_000_000 * 9_000_000 = 9_000_000_000_000
        // / 10_000_000 = 900_000
        // * 10 (rescale from 6 to 7) = 9_000_000
        assert_eq!(to_eurc, 9_000_000i128);

        // Convert back
        let back_to_usdc = client.convert_with_decimals(&to_eurc, &eurc, &usdc, &7u32, &6u32).unwrap();
        // 9_000_000 * 11_111_111 / 1e7 / 10 (rescale from 7 to 6)
        // = (9_000_000 * 11_111_111) / 1e7 / 10
        // = 100_000_000_000_000 / 1e7 / 10 (approximately)
        // ≈ 10_000_000 / 10 = 1_000_000
        assert_eq!(back_to_usdc, 1_000_000i128, "round-trip returns ~original amount");
    }

    #[test]
    fn test_set_price_reciprocal_consistent() {
        let (env, admin, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let usdc = Symbol::new(&env, "USDC");
        // Forward: 1 EURC = 1.1 USDC (11_000_000 at 1e7 scale)
        client.set_price(&admin, &eurc, &usdc, &11_000_000i128);

        // Reverse: 1 USDC = ~0.909... EURC
        // Computed reciprocal: 10^14 / 11_000_000 = 9_090_909 (approximately)
        let result = client.try_set_price(&admin, &usdc, &eurc, &9_090_909i128);
        assert!(result.is_ok(), "reciprocal-consistent price should be accepted");
    }

    #[test]
    fn test_set_price_reciprocal_inconsistent_rejected() {
        let (env, admin, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let usdc = Symbol::new(&env, "USDC");
        // Forward: 1 EURC = 1.1 USDC
        client.set_price(&admin, &eurc, &usdc, &11_000_000i128);

        // Try to set reverse to a wildly inconsistent value (off by 2x)
        let result = client.try_set_price(&admin, &usdc, &eurc, &18_000_000i128);
        assert!(result.is_err(), "reciprocal-inconsistent price should be rejected");
    }

    #[test]
    fn test_round_trip_with_reciprocal_check() {
        let (env, admin, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let usdc = Symbol::new(&env, "USDC");

        // Set forward: 1 EURC = 1.1 USDC
        client.set_price(&admin, &eurc, &usdc, &11_000_000i128);
        // Set reverse with tolerance: 10^14 / 11_000_000 ≈ 9_090_909
        client.set_price(&admin, &usdc, &eurc, &9_090_909i128);

        // Convert forward: 10_000_000 EURC → ~11_000_000 USDC
        let forward = client.convert(&10_000_000i128, &eurc, &usdc);
        assert_eq!(forward, 11_000_000i128);

        // Convert back: 11_000_000 USDC → ~10_000_000 EURC
        // (11_000_000 * 9_090_909) / 1e7 ≈ 10_000_000
        let back = client.convert(&11_000_000i128, &usdc, &eurc);
        // Due to fixed-point rounding, expect ~10M but allow ±1% error
        assert!(back >= 9_900_000i128 && back <= 10_100_000i128, "round-trip within 1%");
    }
}
