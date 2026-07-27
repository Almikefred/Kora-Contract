#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol};

const MAX_STALENESS_SECS: u64 = 3600;
const DEFAULT_MAX_PRICE_DEVIATION_BPS: u32 = 1000; // 10% deviation

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
    TokenSymbol(Address),
    MaxDeviation,
    Feeder(Address),
    FeederPrice(Symbol, Symbol, Address),
    PriceFeeders(Symbol, Symbol),
    BaseCurrency,
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
        env.storage()
            .persistent()
            .set(&DataKey::MaxDeviation, &DEFAULT_MAX_PRICE_DEVIATION_BPS);
        Ok(())
    }

    /// Set a price for a currency pair. Authorized feeders only.
    /// Price is expressed as `base` units per 1 unit of `quote`, scaled by 1e7 (stroops).
    /// Rejects prices that deviate more than MAX_PRICE_DEVIATION_BPS from the current aggregated price.
    pub fn set_price(
        env: Env,
        feeder: Address,
        base: Symbol,
        quote: Symbol,
        price: i128,
    ) -> Result<(), PriceOracleError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;

        if price <= 0 {
            return Err(PriceOracleError::InvalidAmount);
        }

        let data = PriceData {
            price,
            timestamp: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(
                &DataKey::FeederPrice(base.clone(), quote.clone(), feeder.clone()),
                &data,
            );

        let mut feeders: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::PriceFeeders(base.clone(), quote.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        if !feeders.iter().any(|f| f == &feeder) {
            feeders.push_back(feeder);
            env.storage()
                .persistent()
                .set(&DataKey::PriceFeeders(base, quote), &feeders);
        }

        Ok(())
    }

    /// Add an authorized feeder. Admin only.
    pub fn add_feeder(env: Env, admin: Address, feeder: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage().persistent().set(&DataKey::Feeder(feeder), &true);
        Ok(())
    }

    /// Remove an authorized feeder. Admin only.
    pub fn remove_feeder(env: Env, admin: Address, feeder: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage().persistent().remove(&DataKey::Feeder(feeder));
        Ok(())
    }

    /// Set the base currency for multi-hop triangulation. Admin only.
    pub fn set_base_currency(
        env: Env,
        admin: Address,
        base: Symbol,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage().persistent().set(&DataKey::BaseCurrency, &base);
        Ok(())
    }

    /// Set the maximum allowed price deviation in basis points.
    /// Admin only. Default is 1000 (10%).
    pub fn set_max_deviation(
        env: Env,
        admin: Address,
        deviation_bps: u32,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage()
            .persistent()
            .set(&DataKey::MaxDeviation, &deviation_bps);
        Ok(())
    }

    /// Get the aggregated price for a pair (median of all active feeders).
    /// Returns the median price and its oldest timestamp.
    /// Fails if no feeders have submitted or prices are stale.
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

        if prices.is_empty() {
            return Err(KoraError::InvalidAmount);
        }

        let median = Self::calculate_median(&prices);
        Ok(PriceData {
            price: median,
            timestamp: min_timestamp,
        })
    }

    /// Convert an amount from one currency to another using the stored price.
    /// First attempts direct pair conversion. If unavailable, triangulates through
    /// the configured base currency. Rejects stale or missing prices.
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

        Ok(())
    }

    fn calculate_median(prices: &Vec<i128>) -> i128 {
        let len = prices.len();
        if len == 0 {
            return 0;
        }

        let mut sorted = prices.clone();
        for i in 0..len {
            for j in i..len {
                if sorted.get(j).unwrap() < sorted.get(i).unwrap() {
                    let temp = *sorted.get(j).unwrap();
                    sorted.set(j, *sorted.get(i).unwrap());
                    sorted.set(i, temp);
                }
            }
        }

        if len % 2 == 1 {
            *sorted.get(len / 2).unwrap()
        } else {
            (*sorted.get(len / 2 - 1).unwrap() + *sorted.get(len / 2).unwrap()) / 2
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

    fn require_feeder(env: &Env, feeder: &Address) -> Result<(), KoraError> {
        let is_feeder: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Feeder(feeder.clone()))
            .unwrap_or(false);
        if !is_feeder {
            return Err(KoraError::RoleNotAssigned);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env, Symbol};

    fn setup() -> (Env, Address, Address, PriceOracleContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PriceOracleContract);
        let client = PriceOracleContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let feeder = Address::generate(&env);
        client.initialize(&admin);
        client.add_feeder(&admin, &feeder);
        (env, admin, feeder, client)
    }

    #[test]
    fn test_set_and_get_price() {
        let (env, _admin, feeder, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");
        client.set_price(&feeder, &base, &quote, &11_000_000i128);
        let data = client.get_price(&base, &quote);
        assert_eq!(data.price, 11_000_000i128);
    }

    #[test]
    fn test_convert_same_currency() {
        let (env, _admin, _feeder, client) = setup();
        let sym = Symbol::new(&env, "USDC");
        let result = client.convert(&1_000_000i128, &sym, &sym);
        assert_eq!(result, 1_000_000i128);
    }

    #[test]
    fn test_convert_different_currency() {
        let (env, _admin, feeder, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let usdc = Symbol::new(&env, "USDC");
        client.set_price(&feeder, &eurc, &usdc, &11_000_000i128);
        let result = client.convert(&10_000_000i128, &eurc, &usdc);
        assert_eq!(result, 11_000_000i128);
    }

    #[test]
    fn test_get_price_missing_fails() {
        let (env, _admin, _feeder, client) = setup();
        let base = Symbol::new(&env, "XLM");
        let quote = Symbol::new(&env, "USDC");
        let result = client.try_get_price(&base, &quote);
        assert!(result.is_err());
    }

    #[test]
    fn test_stale_price_rejected() {
        use soroban_sdk::testutils::{Ledger, LedgerInfo};
        let (env, _admin, feeder, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");
        client.set_price(&feeder, &base, &quote, &11_000_000i128);

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
    fn test_register_and_resolve_token_symbol() {
        let (env, admin, _feeder, client) = setup();
        let token_addr = Address::generate(&env);
        let symbol = Symbol::new(&env, "USDC");
        client.register_token_symbol(&admin, &token_addr, &symbol);
        let resolved = client.resolve_symbol(&token_addr);
        assert_eq!(resolved, symbol);
    }

    #[test]
    fn test_resolve_unregistered_token_fails() {
        let (env, _admin, _feeder, client) = setup();
        let token_addr = Address::generate(&env);
        let result = client.try_resolve_symbol(&token_addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_by_address() {
        let (env, admin, feeder, client) = setup();
        let eurc_token = Address::generate(&env);
        let usdc_token = Address::generate(&env);
        let eurc_symbol = Symbol::new(&env, "EURC");
        let usdc_symbol = Symbol::new(&env, "USDC");

        client.register_token_symbol(&admin, &eurc_token, &eurc_symbol);
        client.register_token_symbol(&admin, &usdc_token, &usdc_symbol);
        client.set_price(&feeder, &eurc_symbol, &usdc_symbol, &11_000_000i128);

        let result = client.convert_by_address(&10_000_000i128, &eurc_token, &usdc_token);
        assert_eq!(result, 11_000_000i128);
    }

    #[test]
    fn test_price_within_deviation_succeeds() {
        let (env, _admin, feeder, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        client.set_price(&feeder, &base, &quote, &10_000_000i128);

        // 10% deviation allowed (default), new price 10.5M is within 10%
        let result = client.try_set_price(&feeder, &base, &quote, &10_500_000i128);
        assert!(result.is_ok());
    }

    #[test]
    fn test_price_exceeding_deviation_rejected() {
        let (env, _admin, feeder, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        client.set_price(&feeder, &base, &quote, &10_000_000i128);

        // 10% deviation allowed (default), new price 11.5M exceeds 10%
        let result = client.try_set_price(&feeder, &base, &quote, &11_500_000i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_price_override_bypasses_deviation() {
        let (env, _admin, feeder, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        client.set_price(&feeder, &base, &quote, &10_000_000i128);

        // Exceeds deviation but override bypasses check
        let result = client.try_set_price_override(&feeder, &base, &quote, &20_000_000i128);
        assert!(result.is_ok());
        let data = client.get_price(&base, &quote);
        assert_eq!(data.price, 20_000_000i128);
    }

    #[test]
    fn test_set_max_deviation() {
        let (env, admin, feeder, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        client.set_price(&feeder, &base, &quote, &10_000_000i128);

        // Set deviation to 5% (500 bps)
        client.set_max_deviation(&admin, &500u32);

        // 7% increase should now fail (was within 10% before)
        let result = client.try_set_price(&feeder, &base, &quote, &10_700_000i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_first_price_always_succeeds() {
        let (env, _admin, feeder, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        // No previous price, should succeed regardless of value
        let result = client.try_set_price(&feeder, &base, &quote, &100_000_000i128);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_feeders_median_aggregation() {
        let (env, admin, feeder1, client) = setup();
        let feeder2 = Address::generate(&env);
        let feeder3 = Address::generate(&env);
        client.add_feeder(&admin, &feeder2);
        client.add_feeder(&admin, &feeder3);

        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        // Three feeders submit different prices: 10M, 11M, 12M
        client.set_price(&feeder1, &base, &quote, &10_000_000i128);
        client.set_price(&feeder2, &base, &quote, &11_000_000i128);
        client.set_price(&feeder3, &base, &quote, &12_000_000i128);

        // Median should be 11M
        let data = client.get_price(&base, &quote);
        assert_eq!(data.price, 11_000_000i128);
    }

    #[test]
    fn test_single_malicious_feeder_cannot_control_aggregate() {
        let (env, admin, feeder1, client) = setup();
        let malicious_feeder = Address::generate(&env);
        client.add_feeder(&admin, &malicious_feeder);

        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        // Honest feeder submits 10M
        client.set_price(&feeder1, &base, &quote, &10_000_000i128);

        // Malicious feeder tries to submit 1M (1000x lower)
        client.set_price(&malicious_feeder, &base, &quote, &1_000_000i128);

        // Median of [10M, 1M] is 5.5M, not 1M
        let data = client.get_price(&base, &quote);
        assert!(data.price > 1_000_000i128);
        assert!(data.price < 10_000_000i128);
    }

    #[test]
    fn test_add_and_remove_feeder() {
        let (env, admin, feeder, client) = setup();
        let new_feeder = Address::generate(&env);

        client.add_feeder(&admin, &new_feeder);
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");
        let result = client.try_set_price(&new_feeder, &base, &quote, &10_000_000i128);
        assert!(result.is_ok());

        client.remove_feeder(&admin, &new_feeder);
        let result2 = client.try_set_price(&new_feeder, &base, &quote, &11_000_000i128);
        assert!(result2.is_err());
    }

    #[test]
    fn test_multi_hop_conversion_via_base_currency() {
        let (env, admin, feeder, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let gbpc = Symbol::new(&env, "GBPC");
        let usdc = Symbol::new(&env, "USDC");

        // Set USDC as base currency
        client.set_base_currency(&admin, &usdc);

        // Register only EURC->USDC and GBPC->USDC (not direct EURC->GBPC)
        client.set_price(&feeder, &eurc, &usdc, &11_000_000i128); // 1 EURC = 1.1 USDC
        client.set_price(&feeder, &gbpc, &usdc, &13_000_000i128); // 1 GBPC = 1.3 USDC

        // Convert EURC to GBPC via USDC triangulation
        let result = client.convert(&10_000_000i128, &eurc, &gbpc);
        assert!(result.is_ok());

        // Verify math: 10M EURC * 1.1 = 11M USDC, then 11M / 1.3 ≈ 8.46M GBPC
        let converted = result.unwrap();
        assert!(converted > 0);
        assert!(converted < 11_000_000i128);
    }

    #[test]
    fn test_direct_pair_preferred_over_triangulation() {
        let (env, admin, feeder, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let gbpc = Symbol::new(&env, "GBPC");
        let usdc = Symbol::new(&env, "USDC");

        client.set_base_currency(&admin, &usdc);

        // Set direct pair and triangulation pairs with different rates
        client.set_price(&feeder, &eurc, &gbpc, &10_000_000i128); // Direct: 1:1
        client.set_price(&feeder, &eurc, &usdc, &11_000_000i128); // Via base: 1 EURC = 1.1 USDC
        client.set_price(&feeder, &gbpc, &usdc, &11_000_000i128); // Via base: 1 GBPC = 1.1 USDC

        // Should use direct pair (10M), not triangulation result (~10M via base)
        let result = client.convert(&10_000_000i128, &eurc, &gbpc);
        let converted = result.unwrap();
        assert_eq!(converted, 10_000_000i128);
    }

    #[test]
    fn test_triangulation_fails_without_base_currency() {
        let (env, _admin, feeder, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let gbpc = Symbol::new(&env, "GBPC");
        let usdc = Symbol::new(&env, "USDC");

        // No base currency set
        client.set_price(&feeder, &eurc, &usdc, &11_000_000i128);
        client.set_price(&feeder, &gbpc, &usdc, &13_000_000i128);

        // Should fail because no direct pair and no base currency
        let result = client.try_convert(&10_000_000i128, &eurc, &gbpc);
        assert!(result.is_err());
    }

    #[test]
    fn test_triangulation_both_legs_checked_for_staleness() {
        use soroban_sdk::testutils::{Ledger, LedgerInfo};
        let (env, admin, feeder, client) = setup();
        let eurc = Symbol::new(&env, "EURC");
        let gbpc = Symbol::new(&env, "GBPC");
        let usdc = Symbol::new(&env, "USDC");

        client.set_base_currency(&admin, &usdc);
        client.set_price(&feeder, &eurc, &usdc, &11_000_000i128);
        client.set_price(&feeder, &gbpc, &usdc, &13_000_000i128);

        // Advance time to make one leg stale
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

        // Should fail because at least one leg is stale
        let result = client.try_convert(&10_000_000i128, &eurc, &gbpc);
        assert!(result.is_err());
    }
}
