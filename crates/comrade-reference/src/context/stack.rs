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

#[derive(Default, Clone, Debug)]
pub struct Stk {
    pub stack: Vec<Value>,
}

impl Stack for Stk {
    /// push a value onto the stack
    fn push(&mut self, value: Value) {
        self.stack.push(value);
    }

    /// remove the last top value from the stack
    fn pop(&mut self) -> Option<Value> {
        self.stack.pop()
    }

    /// get a reference to the top value on the stack
    fn top(&self) -> Option<Value> {
        self.stack.last().cloned()
    }

    /// peek at the item at the given index
    fn peek(&self, idx: usize) -> Option<Value> {
        if idx >= self.stack.len() {
            return None;
        }
        Some(self.stack[self.stack.len() - 1 - idx].clone())
    }

    /// return the number of values on the stack
    fn len(&self) -> usize {
        self.stack.len()
    }

    /// return if the stack is empty
    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}
