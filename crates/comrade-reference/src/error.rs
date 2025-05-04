//! Crate level error handling.

use crate::context::Rule;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Error parsing the Script
    #[error("Error parsing the Script: {0}")]
    ParseScript(String),

    /// expected `std::boxed::Box<pest::error::Error<pest::Rule>>`, found `pest::error::Error<pest::Rule>`
    #[error("Error parsing the Script: {0}")]
    PestParse(#[from] Box<pest::error::Error<Rule>>),
}
