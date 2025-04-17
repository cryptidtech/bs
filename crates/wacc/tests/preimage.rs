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
    func: &str,
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
    let result = instance.run(func).unwrap();

    if result != expected {
        let mut ctx = instance.store.as_context_mut();
        let context = ctx.data_mut();
        println!("stack:");
        println!("\t top --");
        while let Some(v) = context.rstack.pop() {
            println!("\t\t{:?}\n\t     --", v);
        }
        panic!();
    }

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
fn test_preimage_wast() {
    let _s = span!(Level::INFO, "test_preimage_wast").entered();
    // create the stack to use
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    // the key-value pair store with the message and signature data
    let mut kvp_unlock = Kvp::default();
    // the key-value pair store with the encoded Multikey
    let mut kvp_lock = Kvp::default();

    {
        // unlock
        // set up the key-value pair store with the preimage data
        let _ = kvp_unlock.put(
            "/entry/proof",
            &"for great justice, move every zig!".to_string().into(),
        );

        // load the unlock script
        let script = include_str!(concat!(env!("OUT_DIR"), "/preimage_unlock.wast"))
            .as_bytes()
            .to_vec();

        // run the unlock script to set up the stack
        let mut instance = test_example(
            script,
            "for_great_justice",
            true,
            &kvp_unlock,
            &kvp_unlock,
            &mut pstack,
            &mut rstack,
        );

        // check that the stack is what we expect
        let mut ctx = instance.store.as_context_mut();
        let context = ctx.data_mut();
        assert_eq!(1, context.pstack.len());
        assert_eq!(
            context.pstack.top(),
            Some(Value::Str {
                hint: "".to_string(),
                data: "for great justice, move every zig!".to_string()
            })
        );
    }

    {
        // lock
        // set up the key-value pair store with the sha3 256 hash of the preimage (as serialized
        // Multihash)
        let _ = kvp_lock.put(
            "/hash",
            &hex::decode("16206b761d3b2e7675e088e337a82207b55711d3957efdb877a3d261b0ca2c38e201")
                .unwrap()
                .into(),
        );

        // load the lock script
        let script = include_str!(concat!(env!("OUT_DIR"), "/preimage_lock.wast"))
            .as_bytes()
            .to_vec();

        // run the lock script to check the proof
        let mut instance = test_example(
            script,
            "move_every_zig",
            true,
            &kvp_lock,
            &kvp_unlock,
            &mut pstack,
            &mut rstack,
        );

        // check that the stack is what we expect
        let mut ctx = instance.store.as_context_mut();
        let context = ctx.data_mut();
        assert_eq!(1, context.rstack.len());
        assert_eq!(context.rstack.top(), Some(Value::Success(0)));
    }
}

#[test]
fn test_preimage_wasm() {
    let _s = span!(Level::INFO, "test_preimage_wasm").entered();
    // create the stack to use
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    // the key-value pair store with the message and signature data
    let mut kvp_unlock = Kvp::default();
    // the key-value pair store with the encoded Multikey
    let mut kvp_lock = Kvp::default();

    {
        // unlock
        // set up the key-value pair store with the preimage data
        let _ = kvp_unlock.put(
            "/entry/proof",
            &"for great justice, move every zig!".to_string().into(),
        );

        // load the unlock script
        let script = include_bytes!(concat!(env!("OUT_DIR"), "/preimage_unlock.wasm")).to_vec();

        // run the unlock script to set up the stack
        let mut instance = test_example(
            script,
            "for_great_justice",
            true,
            &kvp_unlock,
            &kvp_unlock,
            &mut pstack,
            &mut rstack,
        );

        // check that the stack is what we expect
        let mut ctx = instance.store.as_context_mut();
        let context = ctx.data_mut();
        assert_eq!(1, context.pstack.len());
        assert_eq!(
            context.pstack.top(),
            Some(Value::Str {
                hint: "".to_string(),
                data: "for great justice, move every zig!".to_string()
            })
        );
    }

    {
        // lock
        // set up the key-value pair store with the sha3 256 hash of the preimage (as serialized
        // Multihash)
        let _ = kvp_lock.put(
            "/hash",
            &hex::decode("16206b761d3b2e7675e088e337a82207b55711d3957efdb877a3d261b0ca2c38e201")
                .unwrap()
                .into(),
        );

        // load the lock script
        let script = include_bytes!(concat!(env!("OUT_DIR"), "/preimage_lock.wasm")).to_vec();

        // run the lock script to check the proof
        let mut instance = test_example(
            script,
            "move_every_zig",
            true,
            &kvp_lock,
            &kvp_unlock,
            &mut pstack,
            &mut rstack,
        );

        // check that the stack is what we expect
        let mut ctx = instance.store.as_context_mut();
        let context = ctx.data_mut();
        assert_eq!(1, context.rstack.len());
        assert_eq!(context.rstack.top(), Some(Value::Success(0)));
    }
}
