#![no_std]

use kora_shared::errors::KoraError;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

const MAX_STALENESS_SECS: u64 = 3600;
const DEFAULT_MAX_PRICE_DEVIATION_BPS: u32 = 1000; // 10% deviation

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
}

#[contract]
pub struct PriceOracleContract;

#[contractimpl]
impl PriceOracleContract {
    pub fn initialize(env: Env, admin: Address) -> Result<(), KoraError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(KoraError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::MaxDeviation, &DEFAULT_MAX_PRICE_DEVIATION_BPS);
        Ok(())
    }

    /// Set a price for a currency pair. Admin only.
    /// Price is expressed as `base` units per 1 unit of `quote`, scaled by 1e7 (stroops).
    /// Rejects prices that deviate more than MAX_PRICE_DEVIATION_BPS from the current stored price.
    pub fn set_price(
        env: Env,
        admin: Address,
        base: Symbol,
        quote: Symbol,
        price: i128,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;

        if price <= 0 {
            return Err(KoraError::InvalidAmount);
        }

        Self::check_price_deviation(&env, &base, &quote, price)?;

        let data = PriceData {
            price,
            timestamp: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::Price(base, quote), &data);
        Ok(())
    }

    /// Set a price with override, bypassing deviation checks.
    /// Admin only. Use for legitimate large moves (e.g., de-peg events).
    pub fn set_price_override(
        env: Env,
        admin: Address,
        base: Symbol,
        quote: Symbol,
        price: i128,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;

        if price <= 0 {
            return Err(KoraError::InvalidAmount);
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

    /// Get the price for a pair. Returns the price and its timestamp.
    /// Fails if the price is stale (older than MAX_STALENESS_SECS) or missing.
    pub fn get_price(
        env: Env,
        base: Symbol,
        quote: Symbol,
    ) -> Result<PriceData, KoraError> {
        let data: PriceData = env
            .storage()
            .persistent()
            .get(&DataKey::Price(base.clone(), quote.clone()))
            .ok_or(KoraError::InvalidAmount)?;

        let age = env
            .ledger()
            .timestamp()
            .saturating_sub(data.timestamp);
        if age > MAX_STALENESS_SECS {
            return Err(KoraError::InvoiceExpired);
        }

        Ok(data)
    }

    /// Convert an amount from one currency to another using the stored price.
    /// Rejects stale or missing prices.
    pub fn convert(
        env: Env,
        amount: i128,
        from: Symbol,
        to: Symbol,
    ) -> Result<i128, KoraError> {
        if from == to {
            return Ok(amount);
        }

        let price_data = Self::get_price(env.clone(), from, to)?;
        let converted = amount
            .checked_mul(price_data.price)
            .and_then(|v| v.checked_div(10_000_000))
            .ok_or(KoraError::ArithmeticOverflow)?;

        if converted <= 0 {
            return Err(KoraError::InvalidAmount);
        }

        Ok(converted)
    }

    /// Register a token address to its currency symbol.
    /// Admin only. Used for address-based conversion lookups.
    pub fn register_token_symbol(
        env: Env,
        admin: Address,
        token: Address,
        symbol: Symbol,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage()
            .persistent()
            .set(&DataKey::TokenSymbol(token), &symbol);
        Ok(())
    }

    /// Resolve a token address to its registered currency symbol.
    pub fn resolve_symbol(env: Env, token: Address) -> Result<Symbol, KoraError> {
        env.storage()
            .persistent()
            .get(&DataKey::TokenSymbol(token))
            .ok_or(KoraError::InvalidAddress)
    }

    /// Convert an amount using token addresses instead of symbols.
    /// Internally resolves both addresses to symbols and delegates to convert.
    pub fn convert_by_address(
        env: Env,
        amount: i128,
        from_token: Address,
        to_token: Address,
    ) -> Result<i128, KoraError> {
        let from_symbol = Self::resolve_symbol(env.clone(), from_token)?;
        let to_symbol = Self::resolve_symbol(env.clone(), to_token)?;
        Self::convert(env, amount, from_symbol, to_symbol)
    }

    fn get_max_deviation(env: &Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::MaxDeviation)
            .unwrap_or(DEFAULT_MAX_PRICE_DEVIATION_BPS)
    }

    fn check_price_deviation(
        env: &Env,
        base: &Symbol,
        quote: &Symbol,
        new_price: i128,
    ) -> Result<(), KoraError> {
        let max_deviation_bps = Self::get_max_deviation(env);

        if let Ok(old_data) = env
            .storage()
            .persistent()
            .get::<_, PriceData>(&DataKey::Price(base.clone(), quote.clone()))
            .ok_or(KoraError::InvalidAmount)
        {
            let old_price = old_data.price;
            let deviation_bps = if new_price > old_price {
                let increase = new_price
                    .checked_sub(old_price)
                    .ok_or(KoraError::ArithmeticOverflow)?;
                increase
                    .checked_mul(10000)
                    .and_then(|v| v.checked_div(old_price))
                    .ok_or(KoraError::ArithmeticOverflow)? as u32
            } else {
                let decrease = old_price
                    .checked_sub(new_price)
                    .ok_or(KoraError::ArithmeticOverflow)?;
                decrease
                    .checked_mul(10000)
                    .and_then(|v| v.checked_div(old_price))
                    .ok_or(KoraError::ArithmeticOverflow)? as u32
            };

            if deviation_bps > max_deviation_bps {
                return Err(KoraError::InvalidAmount);
            }
        }

        Ok(())
    }

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
    fn test_register_and_resolve_token_symbol() {
        let (env, admin, client) = setup();
        let token_addr = Address::generate(&env);
        let symbol = Symbol::new(&env, "USDC");
        client.register_token_symbol(&admin, &token_addr, &symbol);
        let resolved = client.resolve_symbol(&token_addr);
        assert_eq!(resolved, symbol);
    }

    #[test]
    fn test_resolve_unregistered_token_fails() {
        let (env, _admin, client) = setup();
        let token_addr = Address::generate(&env);
        let result = client.try_resolve_symbol(&token_addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_by_address() {
        let (env, admin, client) = setup();
        let eurc_token = Address::generate(&env);
        let usdc_token = Address::generate(&env);
        let eurc_symbol = Symbol::new(&env, "EURC");
        let usdc_symbol = Symbol::new(&env, "USDC");

        client.register_token_symbol(&admin, &eurc_token, &eurc_symbol);
        client.register_token_symbol(&admin, &usdc_token, &usdc_symbol);
        client.set_price(&admin, &eurc_symbol, &usdc_symbol, &11_000_000i128);

        let result = client.convert_by_address(&10_000_000i128, &eurc_token, &usdc_token);
        assert_eq!(result, 11_000_000i128);
    }

    #[test]
    fn test_price_within_deviation_succeeds() {
        let (env, admin, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        client.set_price(&admin, &base, &quote, &10_000_000i128);

        // 10% deviation allowed (default), new price 10.5M is within 10%
        let result = client.try_set_price(&admin, &base, &quote, &10_500_000i128);
        assert!(result.is_ok());
    }

    #[test]
    fn test_price_exceeding_deviation_rejected() {
        let (env, admin, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        client.set_price(&admin, &base, &quote, &10_000_000i128);

        // 10% deviation allowed (default), new price 11.5M exceeds 10%
        let result = client.try_set_price(&admin, &base, &quote, &11_500_000i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_price_override_bypasses_deviation() {
        let (env, admin, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        client.set_price(&admin, &base, &quote, &10_000_000i128);

        // Exceeds deviation but override bypasses check
        let result = client.try_set_price_override(&admin, &base, &quote, &20_000_000i128);
        assert!(result.is_ok());
        let data = client.get_price(&base, &quote);
        assert_eq!(data.price, 20_000_000i128);
    }

    #[test]
    fn test_set_max_deviation() {
        let (env, admin, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        client.set_price(&admin, &base, &quote, &10_000_000i128);

        // Set deviation to 5% (500 bps)
        client.set_max_deviation(&admin, &500u32);

        // 7% increase should now fail (was within 10% before)
        let result = client.try_set_price(&admin, &base, &quote, &10_700_000i128);
        assert!(result.is_err());
    }

    #[test]
    fn test_first_price_always_succeeds() {
        let (env, admin, client) = setup();
        let base = Symbol::new(&env, "EURC");
        let quote = Symbol::new(&env, "USDC");

        // No previous price, should succeed regardless of value
        let result = client.try_set_price(&admin, &base, &quote, &100_000_000i128);
        assert!(result.is_ok());
    }
}
