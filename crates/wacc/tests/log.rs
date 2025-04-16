// SPDX-License-Identifier: FSL-1.1
use std::collections::BTreeMap;
use test_log::test;
use tracing::{span, Level};
use wacc::{
    storage::{Pairs, Stack},
    vm::{Builder, Context, Instance, Value},
};
use wasmtime::{AsContextMut, StoreLimitsBuilder};

const MEMORY_LIMIT: usize = 1 << 22; /* 4MB */

fn test_example<'a>(
    script: Vec<u8>,
    expected: bool,
    current: &'a Kvp,
    proposed: &'a Kvp,
    pstack: &'a mut Stk,
    rstack: &'a mut Stk,
) -> Instance<'a> {
    // build the context
    let context = Context {
        current,
        proposed,
        pstack,
        rstack,
        check_count: 0,
        write_idx: 0,
        context: "/forks/child/".to_string(),
        log: Vec::default(),
        limiter: StoreLimitsBuilder::new()
            .memory_size(MEMORY_LIMIT)
            .instances(2)
            .memories(1)
            .build(),
    };

    // construct the instance
    let mut instance = Builder::new()
        .with_context(context)
        .with_bytes(&script)
        .try_build()
        .unwrap();

    // execute the instance
    let result = instance.run("move_every_zig").unwrap();

    assert_eq!(expected, result);
    instance
}

#[derive(Default)]
struct Kvp {
    pub pairs: BTreeMap<String, Value>,
}

impl Pairs for Kvp {
    /// get a value associated with the key
    fn get(&self, key: &str) -> Option<Value> {
        self.pairs.get(key).cloned()
    }

    /// add a key-value pair to the storage, return previous value if overwritten
    fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
        self.pairs.insert(key.to_string(), value.clone())
    }
}

#[derive(Default)]
struct Stk {
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

#[test]
fn test_log_wast() {
    let _span_ = span!(Level::INFO, "test_log_wast").entered();
    let kvp = Kvp::default();
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    let script = include_str!(concat!(env!("OUT_DIR"), "/log.wast"))
        .as_bytes()
        .to_vec();
    let mut instance = test_example(script, true, &kvp, &kvp, &mut pstack, &mut rstack);
    assert_eq!(b"Hello World!\n".to_vec(), instance.log());
    let mut ctx = instance.store.as_context_mut();
    let context = ctx.data_mut();
    assert_eq!(0, context.pstack.len());
    assert_eq!(0, context.rstack.len());
}

#[test]
fn test_invalid_utf8_wast() {
    let _span_ = span!(Level::INFO, "test_invalid_utf8_wast").entered();
    let kvp = Kvp::default();
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    let script = include_str!(concat!(env!("OUT_DIR"), "/invalid_utf8.wast"))
        .as_bytes()
        .to_vec();
    let mut instance = test_example(script, false, &kvp, &kvp, &mut pstack, &mut rstack);
    let mut ctx = instance.store.as_context_mut();
    let context = ctx.data_mut();
    assert_eq!(0, context.pstack.len());
    assert_eq!(1, context.rstack.len());
    assert_eq!(
        context.rstack.top(),
        Some(Value::Failure(
            "invalid utf-8 sequence of 1 bytes from index 0".to_string()
        ))
    );
}

#[test]
fn test_log_wasm() {
    let _span_ = span!(Level::INFO, "test_log_wasm").entered();
    let kvp = Kvp::default();
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    let script = include_bytes!(concat!(env!("OUT_DIR"), "/log.wasm")).to_vec();
    let mut instance = test_example(script, true, &kvp, &kvp, &mut pstack, &mut rstack);
    assert_eq!(b"Hello World!\n".to_vec(), instance.log());
    let mut ctx = instance.store.as_context_mut();
    let context = ctx.data_mut();
    assert_eq!(0, context.pstack.len());
    assert_eq!(0, context.rstack.len());
}
