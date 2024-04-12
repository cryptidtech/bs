// SPDX-License-Identifier: FSL-1.1
use crate::commands::{State, Terminal, Transition, TransitionFrom};
use provenance_log::script::{self, Script};
use log::debug;
use multicid::cid::{self, Cid};
use multicodec::Codec;
use multihash::SAFE_HASH_CODECS;
use std::{io::{self, BufRead}, path::PathBuf};
use wacc::vm::Compiler;

/// convenience function that hides all of the details
pub async fn load_wasm(path: Option<PathBuf>, cid_hash_codec: Option<Codec>) -> Result<(Script, Cid), crate::error::Error> {
    let mut ctx = Context::new(path, cid_hash_codec);
    crate::commands::run_to_completion(Initial, &mut ctx).await
}

/// SshAgent error
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// plog script error
    #[error(transparent)]
    Script(#[from] provenance_log::Error),
    /// multihash error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),
    /// multicid error 
    #[error(transparent)]
    Multicid(#[from] multicid::Error),
    /// wasmtime compile error
    #[error("compile error: {0}")]
    Compile(String),
    /// invalid file path
    #[error("no path specified")]
    NoPath,
    /// missing script
    #[error("no script loaded")]
    NoScript,
    /// missing codec
    #[error("no cid codec specified")]
    NoCodec,
    /// we're in an error state but no error was specified
    #[error("error state without error specified")]
    MissingError,
    /// error to return when result is called on a non-terminal state
    #[error("error calling result on non-terminal state")]
    NoResult,
    /// something went wrong and you're going to have a hell of a time debugging it
    #[error("wasm load failed")]
    WasmLoadFailed,
}

/// the type returned from this state machine
pub type ReturnValue = (Script, Cid);

// the states, both `Hash` and `Failed` are terminal states
states!(Initial, PathAsk, CodecAsk, Load, Compile, [Hash], [Failed]);

// the happy path
path!(Initial -> PathAsk -> CodecAsk -> Load -> Compile -> Hash);

// can skip over PathAsk, and PathAsk + CodecAsk if we already have them
paths!(Initial -> CodecAsk, Load);

// can skip over CodecAsk
path!(PathAsk -> Load);

// the failure transitions to the `Failed` state
failures!(PathAsk, CodecAsk, Load, Compile, Hash -> Failed);

/// tracks the current state of the wasm loader
pub struct Context {
    // inputs
    path: Option<PathBuf>,
    codec: Option<Codec>,
    // outputs
    cid: Option<Cid>,
    script: Option<Script>,
    error: Option<Error>,
}

impl Context {
    /// contruct a new context for the wasm loader state machine
    pub fn new(path: Option<PathBuf>, codec: Option<Codec>) -> Self  {
        Self {
            // inputs
            path,
            codec,
            // outputs
            script: None,
            cid: None,
            error: None,
        }
    }
}

#[async_trait::async_trait]
impl State<Context, ReturnValue> for Initial {
    /// ensure that we have the precoditions to succeed
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, ReturnValue>, crate::error::Error> {
        // check that we have a path and that it points at a file
        if context.path.is_none() {
            Ok(Transition::next(Self, PathAsk))
        } else if context.codec.is_none() || !SAFE_HASH_CODECS.contains(&context.codec.clone().unwrap()) {
            Ok(Transition::next(Self, CodecAsk))
        } else {
            Ok(Transition::next(Self, Load))
        }
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Initial ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<ReturnValue, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, ReturnValue> for PathAsk {
    /// get the wasm file path from the user
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, ReturnValue>, crate::error::Error> {
        // loop getting the lock file path from the user
        let stdin = io::stdin();
        loop {
            println!("Path to wasm file to load?:");
            let pb = {
                let mut p = String::default();
                match stdin.lock().read_line(&mut p) {
                    Ok(len) if len > 1 => PathBuf::from(p.trim().to_string()),
                    Ok(_) => continue,
                    Err(_) => {
                        context.error = Some(Error::NoPath);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };
            debug!("path = {}", pb.as_os_str().to_string_lossy());

            if !pb.is_file() {
                continue;
            }
            context.path = Some(pb);
            break;
        }

        debug!("got path");

        if context.codec.is_none() {
            Ok(Transition::next(Self, CodecAsk))
        } else {
            Ok(Transition::next(Self, Load))
        }
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("PathAsk ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<ReturnValue, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, ReturnValue> for CodecAsk {
    /// ask for the codec
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, ReturnValue>, crate::error::Error> {

        // loop getting the key type from the user
        let stdin = io::stdin();
        loop {
            println!("Which hash algorithm for the CID, default is 'sha3-256'? ('blake2b-256', 'blake2b-512', 'sha3-256', 'sha3-512'):");
            let codec = {
                let mut c = String::default();
                match stdin.lock().read_line(&mut c) {
                    Ok(len) if len == 1 => "sha3-256".to_string(),
                    Ok(len) if len > 1 => c.trim().to_lowercase(),
                    Ok(_) => "sha3-256".to_string(),
                    Err(_) => {
                        context.error = Some(Error::NoCodec);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };
            debug!("codec = {}", codec);

            // figure out the codec
            let codec = match codec.as_str() {
                "blake2b-256" => Codec::Blake2B256,
                "blake2b-512" => Codec::Blake2B512,
                "sha3-256" => Codec::Sha3256,
                "sha3-512" => Codec::Sha3512,
                _ => {
                    debug!("err: no matching codec");
                    continue
                }
            };
            debug!("codec = {:?}", codec);

            context.codec = Some(codec);
            break;
        }

        debug!("got codec");

        Ok(Transition::next(Self, Load))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("CodecAsk ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<ReturnValue, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, ReturnValue> for Load {
    /// load the script from the file
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, ReturnValue>, crate::error::Error> {
        // try to build a script from the file
        let pb = context.path.take().unwrap();
        match script::Builder::from_code_file(&pb).try_build() {
            Ok(s) => {
                context.script = Some(s);
                Ok(Transition::next(Self, Compile))
            }
            Err(e) => {
                context.error = Some(Error::Script(e));
                Ok(Transition::next(Self, Failed))
            }
        }
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Load ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<ReturnValue, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, ReturnValue> for Compile {
    /// compile the script to check for errors
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, ReturnValue>, crate::error::Error> {
        match {
            if context.script.is_some() {
                let script = context.script.clone().unwrap();
                Compiler::new().with_bytes(script).try_compile().map_err(|e| Error::Compile(e.to_string()))?;
                Ok(())
            } else {
                Err(Error::NoScript)
            }
        } {
            Ok(_) => Ok(Transition::next(Self, Hash)),
            Err(e) => {
                context.error = Some(e);
                Ok(Transition::next(Self, Failed))
            }
        }
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Compile ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<ReturnValue, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, ReturnValue> for Hash {
    /// generate the Hash of the script
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, ReturnValue>, crate::error::Error> {
        match {
            if context.script.is_some() && context.codec.is_some() {
                let script = context.script.clone().unwrap();
                let codec = context.codec.take().unwrap();
                // build the multihash from the script
                let mh = multihash::Builder::new_from_bytes(codec, script)
                    .map_err(|e| Error::Multihash(e))?
                    .try_build()
                    .map_err(|e| Error::Multihash(e))?;
                // build the cid with the multihash
                let cid = cid::Builder::new(Codec::Cidv1)
                    .with_target_codec(Codec::Identity) // wasm scripts are raw binary
                    .with_hash(&mh)
                    .try_build()
                    .map_err(|e| Error::Multicid(e))?;
                Ok(cid)
            } else {
                Err(Error::NoCodec)
            }
        } {
            Ok(cid) => {
                context.cid = Some(cid);
                Ok(Transition::complete(Self))
            }
            Err(e) => {
                context.error = Some(e);
                Ok(Transition::next(Self, Failed))
            }
        }
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Hash ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, context: &mut Context) -> Result<ReturnValue, crate::error::Error> {
        if context.script.is_some() && context.cid.is_some() {
            let script = context.script.take().unwrap();
            let cid = context.cid.take().unwrap();
            Ok((script, cid))
        } else {
            Err(Error::WasmLoadFailed.into())
        }
    }
}

#[async_trait::async_trait]
impl State<Context, ReturnValue> for Failed {
    /// ensure that we have the precoditions to succeed
    async fn next(self: Box<Self>, _context: &mut Context) -> Result<Transition<Context, ReturnValue>, crate::error::Error> {
        Ok(Transition::complete(Self))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Failed".to_string())
    }

    /// return the error
    async fn result(&self, context: &mut Context) -> Result<ReturnValue, crate::error::Error> {
        Err(context.error.take().ok_or::<crate::error::Error>(Error::MissingError.into())?.clone().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::run_to_completion;
    use multicid::EncodedCid;

    macro_rules! bo {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_wasm_ok() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("wat");
        pb.push("first.wat");

        let mut ctx = Context::new(Some(pb), Some(Codec::Sha3256));
        let ret = bo!(run_to_completion(Initial, &mut ctx));
        assert!(ret.is_ok());

        let (script, cid) = ret.unwrap();
        let ecid: EncodedCid = cid.clone().into();
        println!("cid: {:?}", cid);
        println!("encoded cid: {}", ecid);
        println!("script: {:?}", script);
    }
    
    #[test]
    fn test_convenience_fn() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("wat");
        pb.push("first.wat");

        let ret = bo!(load_wasm(Some(pb), Some(Codec::Sha3256)));
        assert!(ret.is_ok());
    }

    #[test]
    fn test_wasm_load_err() {
        // inavlid path
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("none.wat");

        let mut ctx = Context::new(Some(pb), Some(Codec::Sha3256));
        let ret = bo!(run_to_completion(Initial, &mut ctx));
        assert!(ret.is_err());
    }

    #[test]
    fn test_wasm_compile_err() {
        // path to a file with invalide wasm text and it won't compile
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("wontcompile.wat");

        let mut ctx = Context::new(Some(pb), Some(Codec::Sha3256));
        let ret = bo!(run_to_completion(Initial, &mut ctx));
        assert!(ret.is_err());
    }
}
