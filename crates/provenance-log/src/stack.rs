// SPDX-License-Identifier: FSL-1.1
use std::fmt;
use tracing::info;
use wacc::{vm::Value, Stack};

/// Stack is used for both the parameter and return value stacks in the WACC vm
#[derive(Clone, Default)]
pub struct Stk {
    stack: Vec<Value>,
}

impl Stack for Stk {
    /// push a value onto the stack
    fn push(&mut self, value: Value) {
        info!(" push: {:?}", &value);
        self.stack.push(value);
        info!("stack:\n{:?}", &self);
    }

    /// remove the last top value from the stack
    fn pop(&mut self) -> Option<Value> {
        match self.stack.pop() {
            ref r @ Some(ref v) => {
                info!("  pop: {:?}", &v);
                info!("stack:\n{:?}", &self);
                r.clone()
            }
            None => {
                info!("pop from empty stack");
                None
            }
        }
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

const MAX_STR_WIDTH: usize = 32;

impl fmt::Debug for Stk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let values = self
            .stack
            .iter()
            .rev()
            .map(|v| {
                let mut s = format!("{:?}", v);
                if s.len() >= MAX_STR_WIDTH {
                    let (trunc, _) = s.split_at_mut(MAX_STR_WIDTH - 1);
                    s = trunc.to_string();
                    s.push('…');
                }
                s
            })
            .collect::<Vec<String>>();
        let mut first = true;
        let mut s = format!("       ╭─{:─<width$}─╮\n", "─", width = MAX_STR_WIDTH);
        if !values.is_empty() {
            values.iter().for_each(|l| {
                if first {
                    s += format!(" top → │ {: ^width$} │\n", l, width = MAX_STR_WIDTH).as_str();
                    first = false;
                } else {
                    s += format!("       │ {: ^width$} │\n", l, width = MAX_STR_WIDTH).as_str();
                }
                s += format!("       ├─{:─<width$}─┤\n", "─", width = MAX_STR_WIDTH).as_str();
            });
        } else {
            s += format!(" top → │ {: ^width$} │\n", "<empty>", width = MAX_STR_WIDTH).as_str();
        }
        s += format!("       ┆ {:<width$} ┆", " ", width = MAX_STR_WIDTH).as_str();
        f.write_str(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;
    use tracing::{span, Level};

    #[test]
    fn test_debug_empty() {
        let _s = span!(Level::INFO, "test_debug_empty").entered();
        let s = Stk::default();
        info!("\n{:?}", &s);
    }

    #[test]
    fn test_debug_non_empty() {
        let _s = span!(Level::INFO, "test_debug_non_empty").entered();
        let mut s = Stk::default();
        s.push(b"foo".to_vec().into());
        s.push("bar".to_string().into());
        s.push(Value::Failure("bad".to_string()));
    }

    #[test]
    fn test_debug_non_empty_pop() {
        let _s = span!(Level::INFO, "test_debug_non_pop").entered();
        let mut s = Stk::default();
        s.push(b"foo".to_vec().into());
        s.push("bar".to_string().into());
        s.push(Value::Failure("bad".to_string()));
        let _ = s.pop();
    }

    #[test]
    fn test_push_binary() {
        let _s = span!(Level::INFO, "test_push_binary").entered();
        let mut s = Stk::default();
        s.push(b"foo".to_vec().into());
        assert_eq!(s.len(), 1);
        assert_eq!(
            s.top(),
            Some(Value::Bin {
                hint: "".to_string(),
                data: b"foo".to_vec()
            })
        );
    }

    #[test]
    fn test_push_string() {
        let _s = span!(Level::INFO, "test_push_string").entered();
        let mut s = Stk::default();
        s.push("foo".to_string().into());
        assert_eq!(s.len(), 1);
        assert_eq!(
            s.top(),
            Some(Value::Str {
                hint: "".to_string(),
                data: "foo".to_string()
            })
        );
    }

    #[test]
    fn test_push_success() {
        let _s = span!(Level::INFO, "test_push_success").entered();
        let mut s = Stk::default();
        s.push(1.into());
        assert_eq!(s.len(), 1);
        assert_eq!(s.top(), Some(Value::Success(1)));
    }

    #[test]
    fn test_push_failure() {
        let _s = span!(Level::INFO, "test_push_failure").entered();
        let mut s = Stk::default();
        s.push(Value::Failure("bad".to_string()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.top(), Some(Value::Failure("bad".to_string())));
    }

    #[test]
    fn test_pop() {
        let _s = span!(Level::INFO, "test_pop").entered();
        let mut s = Stk::default();
        s.push(1.into());
        s.push(2.into());
        assert_eq!(s.len(), 2);
        assert_eq!(s.top(), Some(Value::Success(2)));
        s.pop();
        assert_eq!(s.len(), 1);
        assert_eq!(s.top(), Some(Value::Success(1)));
    }

    #[test]
    fn test_peek() {
        let _s = span!(Level::INFO, "test_peek").entered();
        let mut s = Stk::default();
        s.push(1.into());
        s.push(2.into());
        assert_eq!(s.len(), 2);
        assert_eq!(s.peek(1), Some(Value::Success(1)));
    }
}
