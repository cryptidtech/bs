// SPDX-License-Identifier: FSL-1.1
use crate::Value;

/// Trait for a value stack
pub trait Stack {
    /// push a value onto the stack
    fn push(&mut self, value: Value);

    /// remove the last top value from the stack
    fn pop(&mut self) -> Option<Value>;

    /// get a reference to the top value on the stack 
    fn top(&self) -> Option<Value>;

    /// peek at the item at the given index
    fn peek(&self, idx: usize) -> Option<Value>;

    /// return the number of values on the stack
    fn len(&self) -> usize;

    /// return if the stack is empty
    fn is_empty(&self) -> bool;
}
