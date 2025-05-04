//! The context that is built and where the script
//! is evaluated

mod pairs;
pub use pairs::Pairs;

mod value;
pub use value::Value;

mod stack;
pub use stack::{Stack, Stk};

mod parser;
pub(crate) use parser::Rule;
use parser::{parse, Expression, Function, Key};

use crate::ApiError;
use multihash::{mh, Multihash};
use multikey::{Multikey, Views as _};
use multisig::Multisig;
use multiutil::prelude::*;

/// The [Context] within which the script is
/// evaluated.
pub(crate) struct Context<P: Pairs, L: Log> {
    /// The Return stack
    pub(crate) current: P,

    /// The Parameters stack
    pub(crate) proposed: P,

    /// The number of checks that have been performed
    pub(crate) check_count: usize,

    /// The Return stack
    pub(crate) rstack: Stk,

    /// The Parameters stack
    pub(crate) pstack: Stk,

    /// Optional domain segment of the /branch/leaf/ key-path. Defaults to "/".
    pub domain: String,

    /// The log implementation for the context
    pub(crate) logger: L,
}

/// Log a message to the console
pub trait Log {
    fn log(&self, msg: &str)
    where
        Self: Sized;
}

impl<P: Pairs, L: Log> Context<P, L> {
    /// Create a new [Context] struct with the given [Current] and [Proposed] key-value stores,
    /// which are bound by both [Pairable].
    pub fn new(current: P, proposed: P, logger: L) -> Self {
        Context {
            current,
            proposed,
            check_count: 0,
            rstack: Stk::default(),
            pstack: Stk::default(),
            domain: "/".to_string(),
            logger,
        }
    }

    /// Parse a script from a string and evaluate it, returning the result
    pub fn run(&mut self, script: &str) -> Result<bool, ApiError> {
        self.logger.log(&format!("Running script: {script}"));
        let expressions = parse(script)?;

        if expressions.is_empty() {
            return Ok(false);
        }

        // Execute each expression in sequence
        // For multiple expressions (separated by semicolons in the original script),
        // we execute all of them and return the result of the last one
        let mut result = false;

        for expr in &expressions {
            result = self.eval(expr);
            // Unlike logical OR, we don't short-circuit between separate statements
        }

        Ok(result)
    }

    /// Evaluate a single expression
    fn eval(&mut self, expr: &Expression) -> bool {
        match expr {
            Expression::Function(func) => self.eval_function(func),
            Expression::And(left, right) => self.eval(left) && self.eval(right),
            Expression::Or(left, right) => self.eval(left) || self.eval(right),
            Expression::Group(inner) => self.eval(inner),
        }
    }

    /// Evaluate a function call
    fn eval_function(&mut self, function: &Function) -> bool {
        match function {
            Function::CheckEq(key) => match key {
                Key::Branch(key) => self.check_eq(&self.branch(key)),
                Key::String(key) => self.check_eq(key),
            },
            Function::CheckSignature(key, msg) => match key {
                Key::Branch(key) => self.check_signature(&self.branch(key), msg),
                Key::String(key) => self.check_signature(key, msg),
            },
            Function::CheckPreimage(preimage) => match preimage {
                Key::Branch(key) => self.check_preimage(&self.branch(key)),
                Key::String(key) => self.check_preimage(key),
            },
            Function::Push(path) => match path {
                Key::Branch(key) => self.push(&self.branch(key)),
                Key::String(key) => self.push(key),
            },
        }
    }

    /// Check the signature of the given key str
    pub fn check_signature(&mut self, key: &str, msg: &str) -> bool {
        self.logger.log(&format!("check_signature({key}, {msg})"));
        let current = self.current.get(key);
        // lookup the keypair for this key
        let pubkey = {
            match &current {
                Some(Value::Bin { hint: _, data }) => match Multikey::try_from(data.as_ref()) {
                    Ok(mk) => mk,
                    Err(e) => {
                        self.logger
                            .log("check_signature: error decoding multikey: {e}");
                        return self.check_fail(&e.to_string());
                    }
                },
                Some(_) => {
                    self.logger
                        .log("check_signature: unexpected value type associated with {key}");
                    return self
                        .check_fail(&format!("unexpected value type associated with {key}"));
                }
                None => {
                    self.logger.log(&format!(
                        "check_signature: no multikey associated with {key}"
                    ));
                    return self.check_fail(&format!("no multikey associated with {key}"));
                }
            }
        };

        self.logger
            .log(&format!("OK check_signature: pubkey: {pubkey:?}"));

        // look up the message that was signed
        let message = {
            match self.proposed.get(msg) {
                Some(Value::Bin { hint: _, data }) => data,
                Some(Value::Str { hint: _, data }) => data.as_bytes().to_vec(),
                Some(_) => {
                    self.logger
                        .log("check_signature: unexpected value type associated with {msg}");
                    return self
                        .check_fail(&format!("unexpected value type associated with {msg}"));
                }
                None => {
                    self.logger
                        .log("check_signature: no message associated with {msg}");
                    return self.check_fail(&format!("no message associated with {msg}"));
                }
            }
        };

        self.logger
            .log(&format!("OK check_signature: message: {message:?}"));

        // make sure we have at least one parameter on the stack
        if self.pstack.is_empty() {
            self.logger.log(&format!(
                "Err not enough parameters on the stack for check_signature: {}",
                self.pstack.len(),
            ));
            return self.check_fail(&format!(
                "not enough parameters ({}) on the stack for check_signature ({key}, {msg})",
                self.pstack.len()
            ));
        }

        // peek at the top item and verify that it is a Multisig
        let sig = {
            match self.pstack.top() {
                Some(Value::Bin { hint: _, data }) => {
                    self.logger.log(&format!(
                        "check_signature: found multisig on stack: {data:?}"
                    ));
                    match Multisig::try_from(data.as_ref()) {
                        Ok(sig) => sig,
                        Err(e) => return self.check_fail(&e.to_string()),
                    }
                }
                _ => return self.check_fail("no multisig on stack"),
            }
        };

        // get the verify view
        let verify_view = match pubkey.verify_view() {
            Ok(v) => v,
            Err(e) => return self.check_fail(&e.to_string()),
        };

        // verify the signature
        match verify_view.verify(&sig, Some(message.as_ref())) {
            Ok(_) => {
                // the signature verification worked so pop the signature arg off
                // of the stack before continuing
                self.logger.log("check_signature: signature verified");
                self.pstack.pop();
                self.succeed()
            }
            Err(e) => {
                self.logger.log("check_signature({key}, {msg}) -> false");
                self.check_fail(&e.to_string())
            }
        }
    }

    /// Check the preimage of the given key
    pub fn check_preimage(&mut self, key: &str) -> bool {
        // look up the hash and try to decode it
        let hash = {
            let current = self.current.get(key);
            match current {
                Some(Value::Bin { hint: _, data }) => match Multihash::try_from(data.as_ref()) {
                    Ok(hash) => hash,
                    Err(e) => return self.check_fail(&e.to_string()),
                },
                Some(_) => {
                    return self
                        .check_fail(&format!("unexpected value type associated with {key}"));
                }
                None => return self.check_fail(&format!("kvp missing key: {key}")),
            }
        };

        // make sure we have at least one parameter on the stack
        if self.pstack.is_empty() {
            self.logger.log(&format!(
                "not enough parameters on the stack for check_preimage: {}",
                self.pstack.len(),
            ));
            return self.check_fail(&format!(
                "not enough parameters on the stack for check_preimage: {}",
                self.pstack.len()
            ));
        }

        // get the preimage data from the stack
        let preimage = {
            match self.pstack.top() {
                Some(Value::Bin { data, hint: _ }) => {
                    match mh::Builder::new_from_bytes(hash.codec(), data) {
                        Ok(builder) => match builder.try_build() {
                            Ok(hash) => hash,
                            Err(e) => return self.check_fail(&e.to_string()),
                        },
                        Err(e) => return self.check_fail(&e.to_string()),
                    }
                }
                Some(Value::Str { hint: _, data }) => {
                    match mh::Builder::new_from_bytes(hash.codec(), data.as_bytes()) {
                        Ok(builder) => match builder.try_build() {
                            Ok(hash) => hash,
                            Err(e) => return self.check_fail(&e.to_string()),
                        },
                        Err(e) => return self.check_fail(&e.to_string()),
                    }
                }
                _ => return self.check_fail("no multihash data on stack"),
            }
        };

        // check that the hashes match
        if hash == preimage {
            // the hash check passed so pop the argument from the stack
            let _ = self.pstack.pop();
            self.succeed()
        } else {
            // the hashes don't match
            self.check_fail("preimage doesn't match")
        }
    }

    /// Verifies the top of the stack matches the value associated with the key
    pub fn check_eq(&mut self, key: &str) -> bool {
        // look up the value associated with the key
        let value = {
            match self.current.get(key) {
                Some(Value::Bin { hint: _, data }) => data,
                Some(Value::Str { hint: _, data }) => data.as_bytes().to_vec(),
                _ => {
                    self.logger.log("check_eq: no value associated with {key}");
                    return self.check_fail(&format!("kvp missing key: {key}"));
                }
            }
        };

        // make sure we have at least one parameter on the stack
        if self.pstack.is_empty() {
            self.logger.log(&format!(
                "not enough parameters on the stack for check_eq: {}",
                self.pstack.len(),
            ));
            return self.check_fail(&format!(
                "not enough parameters on the stack for check_eq: {}",
                self.pstack.len()
            ));
        }

        let stack_value = {
            match self.pstack.top() {
                Some(Value::Bin { hint: _, data }) => data,
                Some(Value::Str { hint: _, data }) => data.as_bytes().to_vec(),
                _ => {
                    self.logger.log("check_eq: no value on the stack");
                    return self.check_fail("no value on the stack");
                }
            }
        };

        // check if equal
        if value == stack_value {
            // the values match so pop the argument from the stack
            let _ = self.pstack.pop();
            self.succeed()
        } else {
            // the values don't match
            self.check_fail("values don't match")
        }
    }

    /// Increment the check counter and to push a FAILURE marker on the return stack
    pub fn check_fail(&mut self, err: &str) -> bool {
        self.logger.log(&format!("check_fail ({err})"));
        // update the context check_count
        self.check_count += 1;
        // fail
        self.fail(err)
    }

    /// Increment the check counter and to push a FAILURE marker on the return stack
    pub fn fail(&mut self, err: &str) -> bool {
        // push the FAILURE onto the return stack
        self.rstack.push(Value::Failure(err.to_string()));
        false
    }

    /// Push a SUCCESS marker onto the return stack
    pub fn succeed(&mut self) -> bool {
        self.logger
            .log(&format!("succeed() -> {}", self.check_count));
        // push the SUCCESS marker with the check count
        self.rstack.push(self.check_count.into());
        // return that we succeeded
        true
    }

    /// Push the value associated with the key onto the parameter stack
    pub fn push(&mut self, key: &str) -> bool {
        self.logger.log(&format!("PUSHING: push(\"{key}\")"));
        // try to look up the key-value pair by key and push the result onto the stack
        match self.current.get(key) {
            Some(v) => {
                self.logger
                    .log(&format!("push: found value associated with {key}"));
                self.pstack.push(v.clone());
                true
            }
            None => {
                self.logger
                    .log(&format!("push: no value associated with {key}"));
                self.fail(&format!("kvp missing key: {key}"))
            }
        }
    }

    /// Calculate the full key given the context
    /// Concatenates the branch key-path with the provided key-path to create a key-path argument for other functions.
    /// When used in lock scripts, the branch key-path is the key-path the lock script is associated with.
    /// When used in unlock scripts, the branch key-path is always /. This function fails if used in a lock script associated with a leaf
    pub fn branch(&self, key: &str) -> String {
        let s = format!("{}{}", self.domain, key);
        self.logger
            .log(&format!("branch({}) -> {}", key, s.as_str()));
        s
    }

    pub(crate) fn rstack(&self) -> Option<Value> {
        self.rstack.top()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::context::Context;
    use std::collections::HashMap;

    struct TestLogger;

    impl Log for TestLogger {
        fn log(&self, msg: &str) {
            println!("{msg}");
        }
    }

    #[derive(Clone, Debug, Default)]
    struct ContextPairs(HashMap<String, Value>);

    impl Pairs for ContextPairs {
        fn get(&self, key: &str) -> Option<Value> {
            self.0.get(key).cloned()
        }

        fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
            self.0.insert(key.to_string(), value.clone())
        }
    }

    fn unlock_script(entry_key: &str, proof_key: &str) -> String {
        let unlock_script = format!(
            r#"
                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            "#
        );

        unlock_script
    }

    /// First lock is /ephemeral and {entry_key}
    fn first_lock_script(entry_key: &str) -> String {
        let first_lock = format!(
            r#"
                // check the first key, which is ephemeral
                check_signature("/ephemeral", "{entry_key}") 
            "#
        );

        first_lock
    }

    /// Other lock script
    fn other_lock_script(entry_key: &str) -> String {
        format!(
            r#"
                // then check a possible threshold sig...
                check_signature("/recoverykey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("/pubkey", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")
            "#
        )
    }
    #[test]
    fn test_push_pairs() {
        let entry_key = "/entry/";

        // unlock
        let entry_data = b"for great justice, move every zig!";
        let proof_key = "/entry/proof";
        let proof_data = hex::decode("4819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03").unwrap();

        let unlock = format!(
            r#"
        // push the serialized Entry as the message
        push("{entry_key}");

        // push the proof data
        push("{entry_key}proof");
    "#
        );

        let mut kvp_unlock = ContextPairs::default();
        // only used for check_signature msg (2ns parameter)
        let proposed = ContextPairs::default();

        let entry_data_vec = entry_data.to_vec();

        kvp_unlock.put(entry_key, &entry_data_vec.clone().into());
        kvp_unlock.put(proof_key, &proof_data.clone().into());

        let mut ctx = Context::new(kvp_unlock, proposed, TestLogger);

        // When the unlock script runs,
        // there should be 2 values on the pstack
        // one for /entry/
        // and one for /entry/proof

        // Run the unlock script
        let result = ctx.run(&unlock);
        assert!(result.is_ok());

        // Check the pstack
        // The first value should be the entry key
        // The second value should be the proof key
        let mut pstack = ctx.pstack.clone();
        assert_eq!(pstack.len(), 2);
        assert_eq!(pstack.pop().unwrap(), proof_data.into());
        assert_eq!(pstack.pop().unwrap(), entry_data_vec.into());
    }

    #[test]
    fn test_eval_scripts() {
        // unlock
        let entry_key = "/entry/";

        let entry_data = b"for great justice, move every zig!";
        let proof_key = "/entry/proof";
        let proof_data = hex::decode("b92483a6c00600010040eda2eceac1ef60c4d54efc7b50d86b198ba12358749e5069dbe0a5ca6c3e7e78912a21c67a18a4a594f904e7df16f798d929d7a8cee57baca89b4ed0dfd1c801").unwrap();

        let mut kvp_lock = ContextPairs::default();
        let mut kvp_unlock = ContextPairs::default();
        // "/entry/" needs to be present on both lock and unlock stacks,
        // since they are used in both the unlock and lock scripts
        kvp_unlock.put(entry_key, &entry_data.to_vec().into());
        kvp_lock.put(entry_key, &entry_data.to_vec().into());
        // "/entry/proof" only needs to be present on the lock stack,
        // since that's where the proof is used
        kvp_lock.put(proof_key, &proof_data.clone().into());

        let unlock = unlock_script(entry_key, proof_key);

        let first_lock = first_lock_script(entry_key);
        let other_lock = other_lock_script(entry_key);

        let locks = [first_lock, other_lock];

        // lock
        let pubkey = "/pubkey";
        let pub_key = hex::decode("ba24ed010874657374206b657901012069c9e8cd599542b5ff7e4cdc4265847feb9785330557edd6a9edae741ed4c3b2").unwrap();
        // "/pubkey" only needs to be present on unlock stack,
        kvp_lock.put(pubkey, &pub_key.into());

        // If we run the unlock script, then the lock script
        // the results of check_signature should be true
        // since our signature is valid
        let mut ctx = Context::new(kvp_lock, kvp_unlock, TestLogger);
        let result = ctx.run(&unlock);
        assert!(result.is_ok());

        // Check the pstack
        // The first value should be the entry key
        // The second value should be the proof key
        let mut pstack = ctx.pstack.clone();
        assert_eq!(pstack.len(), 2);
        assert_eq!(pstack.pop().unwrap(), proof_data.into());
        assert_eq!(pstack.pop().unwrap(), entry_data.to_vec().into());

        // Now run the first lock script
        // The first lock script should run, but fail
        // since we didn't provide a signature for /ephemeral
        let result = ctx.run(&locks[0]);
        assert!(result.is_ok());

        // Check the return stack
        // The length should be 1
        // The value should be Failure("no multikey associated with /ephemeral")
        assert_eq!(ctx.rstack.len(), 1);
        assert_eq!(
            ctx.rstack.top().unwrap(),
            Value::Failure("no multikey associated with /ephemeral".to_string())
        );

        // Now run the second lock script
        let result = ctx.run(&locks[1]);
        assert!(result.is_ok());

        // Check the return stack
        // The length should be 3:
        // - the first lock script failure, since we didn't provide a signature for /ephemeral
        // - the second lock script failure, since we provided a valid signature for /recoverykey
        // - the third lock script success, since we provided a valid signature for /pubkey
        // The value should be Success(2)
        // - since we had 2 failed checks
        eprintln!("Return stack: {:?}", ctx.rstack);
        assert_eq!(ctx.rstack.len(), 3);
        assert_eq!(ctx.rstack.top().unwrap(), Value::Success(2));
    }

    #[test]
    fn generate_test_signatures() {
        use multikey::Views as _;
        use multikey::{self};
        use multisig::Views as _;
        use multiutil::prelude::*;

        let seed = hex::decode("f9ddcd5118319cc69e6985ef3f4ee3b6c591d46255e1ae5569c8662111b7d3c2")
            .unwrap();

        let mk = multikey::Builder::new_from_seed(Codec::Ed25519Priv, seed.as_slice())
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let entry_data = b"for great justice, move every zig!";

        eprintln!("Entry data: {entry_data:?}");

        let signmk = mk.sign_view().unwrap();

        let signature = signmk.sign(entry_data.as_slice(), false, None).unwrap();

        // print out hex signature
        let sig_data = signature.data_view().unwrap();
        let sig_bytes = sig_data.sig_bytes().unwrap();

        eprintln!("Signature bytes: {:?}", &sig_bytes);

        let ms = multisig::Builder::new(Codec::EddsaMsig)
            .with_signature_bytes(&sig_bytes)
            .try_build()
            .unwrap();

        let hex_sig = hex::encode(ms.data_view().unwrap().sig_bytes().unwrap());
        eprintln!("Signature: {hex_sig}");

        assert_eq!(
            hex_sig,
            "4819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03"
        );

        let verify_mk = mk.verify_view().unwrap();
        assert!(verify_mk.verify(&ms, Some(entry_data.as_ref())).is_ok());

        // print pubkey
        let pubkey = mk.conv_view().unwrap();
        let pubkey_bytes: Vec<u8> = pubkey.to_public_key().unwrap().into();

        eprintln!("Pubkey bytes: {pubkey_bytes:?}");
        let hex_pubkey = hex::encode(pubkey_bytes.clone());

        eprintln!("Pubkey: {hex_pubkey}");

        assert_eq!(
            hex_pubkey,
            "ba24ed010874657374206b657901012054d94d7b8a11d6581af4a14bc6451c7a23049018610f108c996968fe8fce9464"
        );
    }
}
