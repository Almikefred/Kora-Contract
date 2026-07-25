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
    /// funding_deadline is too close to the invoice's due_date (#441)
    FundingDeadlineTooCloseToDueDate = 103,
    /// A bidding window is active; direct fund_invoice is not allowed in bidding mode (#440)
    BiddingWindowActive = 104,
    /// The bidding window has closed; no new bids may be submitted (#440)
    BiddingWindowClosed = 105,
    /// No bid found for the given (invoice_id, investor) pair (#440)
    BidNotFound = 106,
    /// Investor already has an active bid on this invoice (#440)
    BidAlreadyExists = 107,

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
    /// Distinct error for empty bytes (semantically different from EmptyString)
    EmptyBytes = 97,
    /// Reentrancy guard triggered
    Reentrancy = 98,
    /// Byte slice has the wrong length (e.g. debtor_hash must be exactly 32 bytes)
    InvalidLength = 99,
    // Upgrade
    NoUpgradeProposed = 100,
    UpgradeTimelockNotElapsed = 101,
    /// Field value exceeds the allowed maximum length
    FieldTooLong = 102,
    // Parameter governance
    ParameterProposalNotFound = 110,
    ParameterProposalAlreadyExecuted = 111,
    NotMultisigSigner = 112,
    AlreadyVoted = 113,
    GovernanceThresholdNotMet = 114,
    GovernanceTimelockNotElapsed = 115,
    InvalidParameterValue = 116,
    /// Cooldown between debtor risk score updates per (verifier, debtor_hash) pair
    ScoreUpdateCooldownNotElapsed = 117,
    /// Marketplace two-phase cancellation
    CancellationPending = 118,
    NoCancellationPending = 119,
}
