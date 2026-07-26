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
    NotInvoiceOwner = 19,

    // Marketplace
    ListingNotFound = 20,
    ListingAlreadyCancelled = 21,
    ListingExpired = 22,
    FundingDeadlinePassed = 23,
    InsufficientFunds = 24,
    ExceedsFundingTarget = 25,
    AlreadyFullyFunded = 26,
    ListingFullyFunded = 27,
    FundingNotExpired = 28,
    RefundAlreadyClaimed = 29,
    NoContribution = 95,

    // Pool
    PoolNotFound = 30,
    PoolAlreadyClosed = 31,
    RepaymentAlreadyMade = 32,
    InsufficientPoolBalance = 33,
    PositionNotFound = 34,
    SaleAlreadyListed = 35,
    SaleNotFound = 36,

    // Treasury
    InvalidFeeRate = 40,
    WithdrawalFailed = 41,
    TokenNotWhitelisted = 42,
    WithdrawalRateLimitExceeded = 43,
    WithdrawalCapTimelockNotElapsed = 44,
    NoCapChangeProposed = 45,

    // Risk
    SMENotRegistered = 50,
    DebtorNotRegistered = 51,
    RiskScoreOutOfRange = 52,
    ComplianceNotAttested = 53,
    // SME profile exists but has not been marked `verified` by a risk_registry verifier
    SMENotVerified = 54,

    // General
    ArithmeticOverflow = 90,
    /// Returned by `safe_sub` when the result would underflow (a < b).
    ArithmeticUnderflow = 91,
    InvalidAddress = 92,
    EmptyString = 93,
    AlreadyInitialized = 94,
    NotInitialized = 96,
    // Distinct error for empty bytes (semantically different from EmptyString)
    EmptyBytes = 97,
    // Reentrancy guard triggered
    Reentrancy = 98,
    // Byte slice has the wrong length (e.g. debtor_hash must be exactly 32 bytes)
    InvalidLength = 99,
    // Upgrade
    NoUpgradeProposed = 100,
    UpgradeTimelockNotElapsed = 101,
    // Field value exceeds the allowed maximum length (was mistakenly = 95; fixed to 103)
    FieldTooLong = 103,
    // Parameter governance
    ParameterProposalNotFound = 110,
    ParameterProposalAlreadyExecuted = 111,
    NotMultisigSigner = 112,
    AlreadyVoted = 113,
    GovernanceThresholdNotMet = 114,
    GovernanceTimelockNotElapsed = 115,
    InvalidParameterValue = 116,
    // Cooldown between debtor risk score updates per (verifier, debtor_hash) pair
    ScoreUpdateCooldownNotElapsed = 117,
    // Marketplace two-phase cancellation
    CancellationPending = 118,
    NoCancellationPending = 119,
    // Minting/amending an invoice would push the SME's aggregate OutstandingExposure
    // above their risk_registry-assigned SmeProfile.credit_limit
    CreditLimitExceeded = 120,
    // A currency symbol is not on the invoice_nft CurrencyAllowlist
    CurrencyNotAllowed = 121,
    // Access-control admin-action multisig
    InvalidThreshold = 122,
    ProposalNotFound = 123,
    ProposalAlreadyExecuted = 124,
    ProposalExpired = 125,
    AlreadyApproved = 126,
    ThresholdNotMet = 127,
    MultisigNotConfigured = 128,
    SignerNotFound = 129,
}
