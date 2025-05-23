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
    let mut instance = match Builder::new()
        .with_context(context)
        .with_bytes(&script)
        .try_build()
    {
        Ok(i) => i,
        Err(e) => {
            println!("builder failed: {}", e);
            panic!()
        }
    };

    // execute the instance
    let result = instance.run(func).unwrap();

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
fn test_pubkey_lock_wast() {
    let _s = span!(Level::INFO, "test_pubkey_lock_wast").entered();
    // create the stack to use
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    // the key-value pair store with the message and signature data
    let mut kvp_unlock = Kvp::default();
    // the key-value pair store with the encoded Multikey
    let mut kvp_lock = Kvp::default();

    {
        // unlock
        // set up the key-value pair store with the message and signature data
        let _ = kvp_unlock.put(
            "/entry/",
            &"for great justice, move every zig!".as_bytes().into(),
        );
        let _ = kvp_unlock.put("/entry/proof", &hex::decode("b92483a6c006000100404acd763546275f5bc03a3270bc68616340b665a5a403b4282d9064fc8fab7260fc0a57a3d2f316f50089da40583797d3618e0d5098061708ec57d7705b249609").unwrap().into());

        // load the unlock script
        let script = include_str!(concat!(env!("OUT_DIR"), "/unlock.wast"))
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
        assert_eq!(context.pstack.top(), Some(Value::Bin { hint: "".to_string(), data: hex::decode("b92483a6c006000100404acd763546275f5bc03a3270bc68616340b665a5a403b4282d9064fc8fab7260fc0a57a3d2f316f50089da40583797d3618e0d5098061708ec57d7705b249609").unwrap() }));
    }

    {
        // lock
        // set up the key-value pair store with the encoded Multikey
        let _ = kvp_lock.put("/pubkey", &hex::decode("ba24ed010874657374206b657901012027bf16566ae7aa3981d42b7391b2934b6f9ef527b4f5493aab9ff89e491bcf36").unwrap().into());

        // load the lock script
        let script = include_str!(concat!(env!("OUT_DIR"), "/lock.wast"))
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
        assert_eq!(2, context.rstack.len());
        // NOTE: the check count is 1 because the check_signature("/tpubkey") failed before the
        // check_signature("/pubkey") succeeded.
        assert_eq!(context.rstack.top(), Some(Value::Success(1)));
    }
}

#[test]
fn test_preimage_lock_wast() {
    let _s = span!(Level::INFO, "test_preimage_lock_wast").entered();
    // create the stack to use
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    // the key-value pair store with the message and signature data
    let mut kvp_unlock = Kvp::default();
    // the key-value pair store with the encoded Multikey
    let mut kvp_lock = Kvp::default();

    {
        // unlock
        // set up the key-value pair store with the message and a preimage
        let _ = kvp_unlock.put("/entry/", &"blah".as_bytes().into());
        let _ = kvp_unlock.put(
            "/entry/proof",
            &"for great justice, move every zig!".as_bytes().into(),
        );

        // load the unlock script
        let script = include_str!(concat!(env!("OUT_DIR"), "/unlock.wast"))
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
            Some(Value::Bin {
                hint: "".to_string(),
                data: b"for great justice, move every zig!".to_vec()
            })
        );
    }

    {
        // lock
        // set up the key-value pair store with the encoded Multihash
        let _ = kvp_lock.put(
            "/hash",
            &hex::decode("16206b761d3b2e7675e088e337a82207b55711d3957efdb877a3d261b0ca2c38e201")
                .unwrap()
                .into(),
        );

        // load the lock script
        let script = include_str!(concat!(env!("OUT_DIR"), "/lock.wast"))
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
        // NOTE: the check_preimage("/hash") call only pops the top preimage off of the stack so
        // the message is still on there giving the len of 2
        assert_eq!(3, context.rstack.len());
        // NOTE: the check count is 2 because the check_signature("/tpubkey") and
        // check_signature("/pubkey") failed before the check_preimage("/hash") succeeded
        assert_eq!(context.rstack.top(), Some(Value::Success(2)));
    }
}

#[test]
fn test_pubkey_lock_wasm() {
    let _s = span!(Level::INFO, "test_pubkey_lock_wasm").entered();
    // create the stack to use
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    // the key-value pair store with the message and signature data
    let mut kvp_unlock = Kvp::default();
    // the key-value pair store with the encoded Multikey
    let mut kvp_lock = Kvp::default();

    {
        // unlock
        // set up the key-value pair store with the message and signature data
        let _ = kvp_unlock.put(
            "/entry/",
            &"for great justice, move every zig!".as_bytes().into(),
        );
        let _ = kvp_unlock.put("/entry/proof", &hex::decode("b92483a6c006000100404acd763546275f5bc03a3270bc68616340b665a5a403b4282d9064fc8fab7260fc0a57a3d2f316f50089da40583797d3618e0d5098061708ec57d7705b249609").unwrap().into());

        // load the unlock script
        let script = include_bytes!(concat!(env!("OUT_DIR"), "/unlock.wasm")).to_vec();

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
        assert_eq!(context.pstack.top(), Some(Value::Bin { hint: "".to_string(), data: hex::decode("b92483a6c006000100404acd763546275f5bc03a3270bc68616340b665a5a403b4282d9064fc8fab7260fc0a57a3d2f316f50089da40583797d3618e0d5098061708ec57d7705b249609").unwrap() }));
    }

    {
        // lock
        // set up the key-value pair store with the encoded Multikey
        let _ = kvp_lock.put("/pubkey", &hex::decode("ba24ed010874657374206b657901012027bf16566ae7aa3981d42b7391b2934b6f9ef527b4f5493aab9ff89e491bcf36").unwrap().into());

        // load the lock script
        let script = include_bytes!(concat!(env!("OUT_DIR"), "/lock.wasm")).to_vec();

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
        assert_eq!(2, context.rstack.len());
        // NOTE: the check count is 1 because the check_signature("/tpubkey") failed before the
        // check_signature("/pubkey") succeeded.
        assert_eq!(context.rstack.top(), Some(Value::Success(1)));
    }
}

#[test]
fn test_preimage_lock_wasm() {
    let _s = span!(Level::INFO, "test_preimage_lock_wasm").entered();
    // create the stack to use
    let mut pstack = Stk::default();
    let mut rstack = Stk::default();
    // the key-value pair store with the message and signature data
    let mut kvp_unlock = Kvp::default();
    // the key-value pair store with the encoded Multikey
    let mut kvp_lock = Kvp::default();

    {
        // unlock
        // set up the key-value pair store with the message and a preimage
        let _ = kvp_unlock.put("/entry/", &"blah".as_bytes().into());
        let _ = kvp_unlock.put(
            "/entry/proof",
            &"for great justice, move every zig!".as_bytes().into(),
        );

        // load the unlock script
        let script = include_bytes!(concat!(env!("OUT_DIR"), "/unlock.wasm")).to_vec();

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
            Some(Value::Bin {
                hint: "".to_string(),
                data: b"for great justice, move every zig!".to_vec()
            })
        );
    }

    {
        // lock
        // set up the key-value pair store with the encoded Multihash
        let _ = kvp_lock.put(
            "/hash",
            &hex::decode("16206b761d3b2e7675e088e337a82207b55711d3957efdb877a3d261b0ca2c38e201")
                .unwrap()
                .into(),
        );

        // load the lock script
        let script = include_bytes!(concat!(env!("OUT_DIR"), "/lock.wasm")).to_vec();

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
        // NOTE: the check_preimage("/hash") call only pops the top preimage off of the stack so
        // the message is still on there giving the len of 2
        assert_eq!(3, context.rstack.len());
        // NOTE: the check count is 2 because the check_signature("/tpubkey") and
        // check_signature("/pubkey") failed before the check_preimage("/hash") succeeded
        assert_eq!(context.rstack.top(), Some(Value::Success(2)));
    }
}
