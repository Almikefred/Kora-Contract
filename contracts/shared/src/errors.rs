use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum KoraError {
    // Auth & Access
    Unauthorized = 1,
    NotAdmin = 2,
    NotVerifier = 3,
    ProtocolPaused = 4,
    AlreadyPaused = 5,
    NotPaused = 6,
    RoleNotAssigned = 7,

    // Invoice
    InvoiceNotFound = 10,
    InvoiceAlreadyExists = 11,
    InvalidInvoiceStatus = 12,
    InvoiceExpired = 13,
    InvalidAmount = 14,
    InvalidDueDate = 15,
    InvalidRiskScore = 16,
    InvalidCid = 17,
    InvoiceFrozen = 18,

    // Marketplace
    ListingNotFound = 20,
    ListingAlreadyCancelled = 21,
    FundingDeadlinePassed = 23,
    ExceedsFundingTarget = 25,
    ListingFullyFunded = 27,
    FundingNotExpired = 28,
    RefundAlreadyClaimed = 29,
    NoContribution = 95,

    // Pool
    PoolNotFound = 30,
    PoolAlreadyClosed = 31,
    RepaymentAlreadyMade = 32,
    /// Also covers `risk_registry`'s "insufficient stake" condition (merged to stay
    /// under Soroban's 50-variant contracterror cap).
    InsufficientPoolBalance = 33,
    PositionNotFound = 34,
    /// Also covers `financing_pool`'s "position already listed for sale" condition
    /// (merged to stay under Soroban's 50-variant contracterror cap).
    AlreadyInitialized = 94,
    SaleNotFound = 36,

    // Treasury
    InvalidFeeRate = 40,
    TokenNotWhitelisted = 42,
    WithdrawalRateLimitExceeded = 43,
    /// Also covers `treasury`'s "no withdrawal-cap proposal pending" and
    /// `access_control`'s "no upgrade proposal pending" conditions (merged to stay
    /// under Soroban's 50-variant contracterror cap).
    NoUpgradeProposed = 100,

    // Risk
    /// Also covers `risk_registry`'s "debtor not registered" condition (merged to
    /// stay under Soroban's 50-variant contracterror cap).
    SMENotRegistered = 50,
    ComplianceNotAttested = 53,

    // General
    // `InvalidAmount` (above, = 14) also covers `access_control`'s "invalid
    // governance parameter value" condition (merged to stay under Soroban's
    // 50-variant contracterror cap).
    ArithmeticOverflow = 90,
    /// Returned by `safe_sub` when the result would underflow (a < b).
    ArithmeticUnderflow = 91,
    InvalidAddress = 92,
    EmptyString = 93,
    NotInitialized = 96,
    // Distinct error for empty bytes (semantically different from EmptyString)
    EmptyBytes = 97,
    // Reentrancy guard triggered
    Reentrancy = 98,
    // Upgrade / timelock. Also covers `treasury`'s withdrawal-cap timelock,
    // `access_control`'s governance timelock, and `risk_registry`'s debtor
    // score-update cooldown (merged to stay under Soroban's 50-variant cap).
    UpgradeTimelockNotElapsed = 101,
    // Field value exceeds the allowed maximum length (was mistakenly = 95; fixed to 103)
    FieldTooLong = 103,
    // Parameter governance
    ParameterProposalNotFound = 110,
    /// Also covers `access_control`'s "caller is not a configured multisig signer"
    /// and "governance approval threshold not met" conditions, and `access_control`'s
    /// "already voted" condition maps here as well (merged to stay under Soroban's
    /// 50-variant contracterror cap).
    // `Unauthorized` (above, = 1) also covers `access_control`'s "caller is not
    // a configured multisig signer" and "governance approval threshold not met"
    // conditions, and its "already voted" condition maps to
    // `ParameterProposalAlreadyExecuted` above (merged to stay under Soroban's
    // 50-variant contracterror cap).
    ParameterProposalAlreadyExecuted = 111,
    // Marketplace two-phase cancellation
    CancellationPending = 118,
    NoCancellationPending = 119,
}
