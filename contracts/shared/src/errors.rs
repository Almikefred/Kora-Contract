use soroban_sdk::contracterror;

/// Common validation/arithmetic errors shared by every contract's
/// `kora_shared::validation` and `kora_shared::reentrancy` helpers.
///
/// Kept deliberately small: Soroban's `#[contracterror]` macro caps an error
/// enum at 50 variants (`SCSpecUDTErrorEnumV0.cases<50>` in the XDR spec).
/// Domain-specific errors belong on each contract's own local error enum,
/// which implements `From<CommonError>` so `?` still works through the
/// shared validation helpers.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CommonError {
    InvalidAmount = 1,
    InvalidDueDate = 2,
    InvalidRiskScore = 3,
    InvalidCid = 4,
    InvalidFeeRate = 5,
    InvalidAddress = 6,
    EmptyString = 7,
    EmptyBytes = 8,
    FieldTooLong = 9,
    ArithmeticOverflow = 10,
    /// Returned by `safe_sub` when the result would underflow (a < b).
    ArithmeticUnderflow = 11,
    /// Reentrancy guard triggered.
    Reentrancy = 12,
}
