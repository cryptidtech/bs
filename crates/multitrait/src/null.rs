// SPDX-License-Idnetifier: Apache-2.0
/// This trait is for multiformat objects that have a NULL value
pub trait Null {
    /// return an instance of Self where is_null(&self) -> true
    fn null() -> Self;
    /// verify if self is the null value
    fn is_null(&self) -> bool;
}

/// This trait is a fallible version of Null
pub trait TryNull: Sized {
    /// the error type to return when constructing a null value fails
    type Error;

    /// try to construct a Null value of Self 
    fn try_null() -> Result<Self, Self::Error>;
    /// verify if self is the null value
    fn is_null(&self) -> bool;
}
