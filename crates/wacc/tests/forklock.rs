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
fn test_branch_lock_wast() {
    let _span_ = span!(Level::INFO, "test_branch_lock_wast").entered();
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
        let _ = kvp_unlock.put("/entry/proof", &hex::decode("3983a6c0060001004076fee92ca796162b5e37a84b4150da685d636491b43c1e2a1fab392a7337553502588a609075b56c46b5c033b260d8d314b584e396fc2221c55f54843679ee08").unwrap().into());
        let _ = kvp_unlock.put("/entry/vlad", &hex::decode("073b2076aaffffc8504500381356752d02ac534b3f267439fb892f5c0a40bf8a654cef017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap().into());

        // load the unlock script
        let script = include_str!(concat!(env!("OUT_DIR"), "/fork_unlock.wast"))
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
        assert_eq!(2, context.pstack.len());
        assert_eq!(context.pstack.top(), Some(Value::Bin { hint: "".to_string(), data: hex::decode("073b2076aaffffc8504500381356752d02ac534b3f267439fb892f5c0a40bf8a654cef017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap() }));
        assert_eq!(context.pstack.peek(1), Some(Value::Bin { hint: "".to_string(), data: hex::decode("3983a6c0060001004076fee92ca796162b5e37a84b4150da685d636491b43c1e2a1fab392a7337553502588a609075b56c46b5c033b260d8d314b584e396fc2221c55f54843679ee08").unwrap() }));
    }

    {
        // lock
        // set up the key-value pair store with the encoded Multikey
        let _ = kvp_lock.put("/forks/child/pubkey", &hex::decode("3aed010874657374206b657901012084d515ef051e07d597f3c14ac09e5a9d5012c659c196d96db5c6b98ea552f603").unwrap().into());
        let _ = kvp_lock.put("/forks/child/vlad", &hex::decode("073b2076aaffffc8504500381356752d02ac534b3f267439fb892f5c0a40bf8a654cef017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap().into());

        // load the lock script
        let script = include_str!(concat!(env!("OUT_DIR"), "/fork_lock.wast"))
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
        assert_eq!(3, context.rstack.len());
        // NOTE: the check count is 1 because the check_signature(branch("pubkey")) failed before the
        // check_signature(branch("pubkey")) succeeded.
        assert_eq!(context.rstack.top(), Some(Value::Success(1)));
    }
}
