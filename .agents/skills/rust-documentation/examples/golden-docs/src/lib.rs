#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! A small crate demonstrating executable API documentation.

/// Errors returned by [`parse_port`].
#[derive(Debug, PartialEq, Eq)]
pub enum ParsePortError {
    /// The input was not an unsigned integer.
    InvalidNumber,
    /// Port zero is not accepted by this contract.
    Zero,
}

/// Parse a nonzero TCP or UDP port number.
///
/// # Errors
///
/// Returns [`ParsePortError::InvalidNumber`] for non-numeric input and
/// [`ParsePortError::Zero`] when the parsed value is zero.
///
/// # Examples
///
/// ```
/// use rust_documentation_golden::parse_port;
///
/// assert_eq!(parse_port("8080"), Ok(8080));
/// assert!(parse_port("invalid").is_err());
/// ```
pub fn parse_port(input: &str) -> Result<u16, ParsePortError> {
    let value = input
        .parse::<u16>()
        .map_err(|_| ParsePortError::InvalidNumber)?;
    if value == 0 {
        return Err(ParsePortError::Zero);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero() {
        assert_eq!(parse_port("0"), Err(ParsePortError::Zero));
    }
}
