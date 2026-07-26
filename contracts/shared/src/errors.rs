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
    // Multisig (B2) — referenced by access_control but previously undefined; restored.
    InvalidThreshold = 120,
    ProposalNotFound = 121,
    ProposalAlreadyExecuted = 122,
    ProposalExpired = 123,
    AlreadyApproved = 124,
    ThresholdNotMet = 125,
    MultisigNotConfigured = 126,
    SignerNotFound = 127,
    // Previously undefined but referenced elsewhere; restored.
    CreditLimitExceeded = 128,
    CurrencyNotAllowed = 129,
    NotInvoiceOwner = 130,
    // Treasury — recipient allowlist/timelock (#457)
    RecipientNotAllowed = 131,
    NoRecipientProposed = 132,
    RecipientTimelockNotElapsed = 133,
    // Treasury — insurance/loss reserve (#458)
    ReserveCallerNotAuthorized = 134,
    InsufficientReserveBalance = 135,
    // Treasury — multisig quorum gate (#455)
    /// A highest-risk function was called directly while a multisig with threshold > 1
    /// is configured — callers must use propose/approve/execute_treasury_action instead.
    QuorumRequired = 136,
}
