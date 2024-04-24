// SPDX-License-Identifier: FSL-1.1
use crate::{keychain::KeyEntry, commands::{key, vlad, wasm, State, Terminal, Transition, TransitionFrom}};
use log::debug;
use multicid::{EncodedCid, EncodedVlad, Vlad};
use multicodec::Codec;
use multikey::EncodedMultikey;
use provenance_log::{Key, Log, Op, OpId, Script, Value};
use std::io::{self, BufRead};

/// convenience function that hides all of the details
pub async fn gen(purpose: &str) -> Result<Generated, crate::error::Error> {
    let mut ctx = Context::new(purpose);
    crate::commands::run_to_completion(Initial, &mut ctx).await
}

/// SshAgent error
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// multihash error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),
    /// multikey error
    #[error(transparent)]
    Multikey(#[from] multikey::Error),
    /// multicid error
    #[error(transparent)]
    Multicid(#[from] multicid::Error),
    /// missing codec
    #[error("no op type given")]
    NoOpId,
    /// missing comment
    #[error("no op key-path given")]
    NoOpPath,
    /// missing answer
    #[error("no op value given")]
    NoOpValue,
    /// we're in an error state but no error was specified
    #[error("error state without error specified")]
    NoError,
    /// we're in an error state but no error was specified
    #[error("not answer given")]
    NoAnswer,
    /// error to return when result is called on a non-terminal state
    #[error("error calling result on non-terminal state")]
    NoResult,
    /// something went wrong and you're going to have a hell of a time debugging it
    #[error("plog generation failed")]
    GenerationFailed,
}

/// The vlad generation returns the following type
#[derive(Clone, Debug, Default)]
pub struct Generated {
    /// the generated vlad for the plog
    pub vlad: Vlad,
    /// the provenance log
    pub plog: Log,
    /// the keys generated during the process
    pub generated_keys: Vec<KeyEntry>,
}

// the states
states!([Initial], VladGen, OpAsk, LockWasm, UnlockWasm, Generate, [Failed]);

// the Initial state is the main menue so we go to other states and back
path!(Initial -> VladGen -> Initial);
path!(Initial -> OpAsk -> Initial);
path!(Initial -> LockWasm -> Initial);
path!(Initial -> UnlockWasm -> Initial);
path!(Initial -> Generate -> Initial);

// OpAsk is repeatable
path!(OpAsk -> OpAsk);

// LockWasm is repeatable
path!(LockWasm -> LockWasm);

// all of the Failed paths
failures!(Initial, VladGen, OpAsk, LockWasm, UnlockWasm, Generate -> Failed);

/// tracks the current state of the plog generator
#[derive(Default)]
pub struct Context {
    // inputs
    purpose: String,
    // state
    // from vlad::gen:
    ephemeral: Option<KeyEntry>,
    first: Option<Script>,
    // from OpAsk:
    ops: Vec<Op>,
    // from wasm::load:
    locks: Vec<Script>,
    unlock: Option<Script>,
    // outputs
    generated: Option<Generated>,
    error: Option<crate::Error>,
}

impl Context {
    /// contruct a new context for the key generator
    pub fn new(purpose: &str) -> Self {
        Self {
            purpose: purpose.to_string(),
            .. Default::default()
        }
    }
}

#[async_trait::async_trait]
impl State<Context, Generated> for Initial {
    /// ensure that we have the precoditions to succeed
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, Generated>, crate::error::Error> {
        // loop getting the key type from the user
        let stdin = io::stdin();
        loop {
            // output what we're doing
            println!("Main Menu, Generating Provenance Log {}\n", &context.purpose);
            println!("\t1. Generate a Vlad");
            println!("\t2. Set the Ops");
            println!("\t3. Set the Locks");
            println!("\t4. Set the Unlock");
            println!("\t5. Generate");
            println!("\t6. Exit");

            let choice = {
                let mut c = String::default();
                match stdin.lock().read_line(&mut c) {
                    Ok(len) if len == 1 => continue,
                    Ok(len) if len > 1 => c.trim().to_lowercase(),
                    Ok(_) => continue,
                    Err(_) => {
                        context.error = Some(Error::NoAnswer);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };
            debug!("{choice}");

            match choice.as_str() {
                "1" => return Ok(Transition::next(Self, VladGen)),
                "2" => return Ok(Transition::next(Self, OpAsk)),
                "3" => return Ok(Transition::next(Self, LockWasm)),
                "4" => return Ok(Transition::next(Self, UnlockWasm)),
                "5" => return Ok(Transition::next(Self, Generate)),
                "6" => break,
                _ => continue,
            }
        }
        Ok(Transition::complete(Self))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Initial ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<Generated, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, Generated> for VladGen {
    /// ask for the codec
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, Generated>, crate::error::Error> {
        let ret = match vlad::gen(&context.purpose, None).await {
            Ok(v) => v,
            Err(e) => {
                context.error = Some(e);
                return Ok(Transition::next(Self, Failed));
            }
        };

        let m: EncodedVlad = ret.vlad.clone().into();
        debug!("{}", m);

        context.ephemeral = Some(ret.ephemeral);

        let vg = Generated {
            vlad: ret.vlad,
            .. Default::default()
        };
        context.generated = Some(vg);
        Ok(Transition::next(Self, Initial))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("VladGen ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<Generated, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, Generated> for OpAsk {
    /// compile the script to check for errors
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, Generated>, crate::error::Error> {
        // loop getting the key type from the user
        let stdin = io::stdin();
        let mut generated_keys = Vec::default();
        let mut ops = Vec::default();
        loop {
            println!("Which op to add (default is 'noop')? ('noop', 'update', 'delete'):");
            let op_type = {
                let mut ot = String::default();
                match stdin.lock().read_line(&mut ot) {
                    Ok(len) if len == 1 => "noop".to_string(),
                    Ok(len) if len > 1 => ot.trim().to_lowercase(),
                    Ok(_) => "noop".to_string(),
                    Err(_) => {
                        context.error = Some(Error::NoOpId);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };
            debug!("op_type = {}", op_type);

            // figure out the op id
            let opid = match OpId::try_from(op_type.as_str()) {
                Ok(o) => o,
                Err(_) => {
                    context.error = Some(Error::NoOpId);
                    return Ok(Transition::next(Self, Failed));
                }
            };

            println!("Which path (default is '/')?:");
            let key_path = {
                let mut kp = String::default();
                match stdin.lock().read_line(&mut kp) {
                    Ok(len) if len == 1 => "/".to_string(),
                    Ok(len) if len > 1 => kp.trim().to_lowercase(),
                    Ok(_) => "/".to_string(),
                    Err(_) => {
                        context.error = Some(Error::NoOpPath);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };
            debug!("key_path = {}", key_path);

            // figure out the op path
            let oppath = match Key::try_from(op_type.as_str()) {
                Ok(o) => o,
                Err(_) => {
                    context.error = Some(Error::NoOpPath);
                    return Ok(Transition::next(Self, Failed));
                }
            };

            let op = match opid {
                OpId::Update => {
                    println!("generating a new key for the value");
                    let key_entry = match key::gen(&context.purpose,
                            Some(Codec::Ed25519Pub),
                            Some("new key".to_string()),
                            (None, None)).await {
                        Ok(v) => v,
                        Err(e) => {
                            context.error = Some(e);
                            return Ok(Transition::next(Self, Failed));
                        }
                    };

                    let m: EncodedMultikey = key_entry.pubkey.clone().into();
                    debug!("generated key {}", m);

                    // remember the generated key for later
                    generated_keys.push(key_entry.clone());
                    
                    Op::Update(oppath, Value::Data(key_entry.pubkey.clone().into()))
                }
                OpId::Noop => Op::Noop(oppath),
                OpId::Delete => Op::Delete(oppath),
            };

            ops.push(op);

            println!("Done? (Y/n):");
            let yn = {
                let mut yn = String::default();
                match stdin.lock().read_line(&mut yn) {
                    Ok(len) if len == 1 => "y".to_string(),
                    Ok(len) if len > 1 => yn.trim().to_lowercase(),
                    Ok(_) => "y".to_string(),
                    Err(_) => {
                        context.error = Some(Error::NoAnswer);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };

            if yn == "y" {
                break;
            }
        }

        debug!("got ops");

        let vg = match context.generated {
            Some(vg) => vg,
            None => Generated::default(),
        };
        context.ops.append(&mut ops);
        vg.generated_keys = generated_keys;
        context.generated = Some(vg);
        Ok(Transition::next(Self, Initial))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("OpAsk ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<Generated, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, Generated> for LockWasm {
    /// compile the script to check for errors
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, Generated>, crate::error::Error> {
        // loop getting the key type from the user
        let stdin = io::stdin();
        let locks = Vec::default();
        loop {
            println!("Which path (default is '/')?:");
            let lock_path = {
                let mut lp = String::default();
                match stdin.lock().read_line(&mut lp) {
                    Ok(len) if len == 1 => "/".to_string(),
                    Ok(len) if len > 1 => lp.trim().to_lowercase(),
                    Ok(_) => "/".to_string(),
                    Err(_) => {
                        context.error = Some(Error::NoOpPath);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };
            debug!("lock_path = {}", lock_path);

            // figure out the op path
            let lock_path = match Key::try_from(lock_path.as_str()) {
                Ok(o) => o,
                Err(_) => {
                    context.error = Some(Error::NoOpPath);
                    return Ok(Transition::next(Self, Failed));
                }
            };

            // get the lock script
            let ret = match wasm::load(&context.purpose, None, Some(Codec::Sha3256)).await {
                Ok(v) => v,
                Err(e) => {
                    context.error = Some(e);
                    return Ok(Transition::next(Self, Failed));
                }
            };

            let m: EncodedCid = ret.cid.clone().into();
            debug!("{}", m);

            locks.push(ret.script);

            println!("Done? (Y/n):");
            let yn = {
                let mut yn = String::default();
                match stdin.lock().read_line(&mut yn) {
                    Ok(len) if len == 1 => "y".to_string(),
                    Ok(len) if len > 1 => yn.trim().to_lowercase(),
                    Ok(_) => "y".to_string(),
                    Err(_) => {
                        context.error = Some(Error::NoAnswer);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };

            if yn == "y" {
                break;
            }
        }

        debug!("got locks");

        context.locks.append(&mut locks);
        Ok(Transition::next(Self, Initial))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("OpAsk ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<Generated, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}


#[async_trait::async_trait]
impl State<Context, Generated> for UnlockWasm {
    /// ask for the codec
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, Generated>, crate::error::Error> {
        let ret = match wasm::load(&context.purpose, None, Some(Codec::Sha3256)).await {
            Ok(v) => v,
            Err(e) => {
                context.error = Some(e);
                return Ok(Transition::next(Self, Failed));
            }
        };

        let m: EncodedCid = ret.cid.clone().into();
        debug!("{}", m);
        context.unlock = Some(ret.script);
        Ok(Transition::next(Self, Initial))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Lock ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<Generated, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, Generated> for Generate {
    /// generate the Hash of the script
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, Generated>, crate::error::Error> {

        let vg = match context.generated {
            Some(vg) => vg,
            None => {
                context.error = Some(Error::GenerationFailed);
                return Ok(Transition::next(Self, Failed));
            }
        };

        // generate the entry


        Ok(Transition::next(Self, Initial))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Generate ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, context: &mut Context) -> Result<Generated, crate::error::Error> {
        if context.generated.is_some() {
            Ok(context.generated.take().unwrap())
        } else {
            Err(Error::GenerationFailed.into())
        }
    }
}

#[async_trait::async_trait]
impl State<Context, Generated> for Failed {
    /// ensure that we have the precoditions to succeed
    async fn next(self: Box<Self>, _context: &mut Context) -> Result<Transition<Context, Generated>, crate::error::Error> {
        Ok(Transition::complete(Self))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Failed".to_string())
    }

    /// return the error
    async fn result(&self, context: &mut Context) -> Result<Generated, crate::error::Error> {
        Err(context.error.take().ok_or::<crate::error::Error>(Error::NoError.into())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::run_to_completion;
    use multicid::EncodedVlad;

    macro_rules! bo {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    /*
    #[test]
    fn test_plog_gen_ok() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("wat");
        pb.push("first.wat");

        let mut ctx = Context::new(Some(pb));
        let ret = bo!(run_to_completion(Initial, &mut ctx));
        assert!(ret.is_ok());

        let vg = ret.unwrap();
        let evlad: EncodedVlad = vg.vlad.clone().into();
        println!("vlad: {:?}", vg.vlad);
        println!("encoded vlad: {}", evlad);
    }
    
    #[test]
    fn test_convenience_fn() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("wat");
        pb.push("first.wat");

        let ret = bo!(vlad_gen(Some(pb)));
        assert!(ret.is_ok());
    }
    */
}
