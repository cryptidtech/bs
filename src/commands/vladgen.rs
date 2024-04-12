// SPDX-License-Identifier: FSL-1.1
use crate::{keychain::KeyEntry, commands::{wasm::load_wasm, keygen::key_gen, State, Terminal, Transition, TransitionFrom}};
use log::debug;
use multicid::{vlad, Cid, EncodedCid, Vlad};
use multicodec::Codec;
use provenance_log::Script;
use std::path::PathBuf;

/// convenience function that hides all of the details
pub async fn vlad_gen(lock: Option<PathBuf>) -> Result<VladGen, crate::error::Error> {
    let mut ctx = Context::new(lock);
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
    #[error("no key codec collected from user")]
    NoCodec,
    /// missing comment
    #[error("no comment collected from user")]
    NoComment,
    /// missing answer
    #[error("no answer collected from user")]
    NoAnswer,
    /// we're in an error state but no error was specified
    #[error("error state without error specified")]
    NoError,
    /// error to return when result is called on a non-terminal state
    #[error("error calling result on non-terminal state")]
    NoResult,
    /// something went wrong and you're going to have a hell of a time debugging it
    #[error("vlad generation failed")]
    VladGenerationFailed,
}

/// The vlad generation returns the following type
#[derive(Clone, Debug, Default)]
pub struct VladGen {
    /// the first lock script referenced by the cid
    pub script: Script,
    /// the cid for the first lock script
    pub cid: Cid,
    /// the generated vlad for the plog
    pub vlad: Vlad,
    /// the ephemeral key generated to sign the cid
    pub key: KeyEntry,
}

// the states
states!(Initial, Lock, KeyGen, [Generate], [Failed]);

// the happy path
path!(Initial -> Lock -> KeyGen -> Generate);

// from CommentAsk we can skip ThresholAsk
path!(Initial -> KeyGen);

// all of the Failed paths
failures!(Lock, KeyGen, Generate -> Failed);

/// tracks the current state of the wasm loader
#[derive(Default)]
pub struct Context {
    // inputs
    lock: Option<PathBuf>,
    // outputs
    generated: Option<VladGen>,
    error: Option<crate::Error>,
}

impl Context {
    /// contruct a new context for the key generator
    pub fn new(lock: Option<PathBuf>) -> Self  {
        Self {
            lock,
            .. Default::default()
        }
    }
}

#[async_trait::async_trait]
impl State<Context, VladGen> for Initial {
    /// ensure that we have the precoditions to succeed
    async fn next(self: Box<Self>, _context: &mut Context) -> Result<Transition<Context, VladGen>, crate::error::Error> {
        // output what we're doing
        println!("Generating vlad");
        Ok(Transition::next(Self, Lock))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Initial ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<VladGen, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, VladGen> for Lock {
    /// ask for the codec
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, VladGen>, crate::error::Error> {
        let (script, cid) = match load_wasm(context.lock.clone(), Some(Codec::Sha3256)).await {
            Ok(v) => v,
            Err(e) => {
                context.error = Some(e);
                return Ok(Transition::next(Self, Failed));
            }
        };

        let m: EncodedCid = cid.clone().into();
        debug!("{}", m);

        let vg = VladGen {
            script,
            cid,
            .. Default::default()
        };
        context.generated = Some(vg);
        Ok(Transition::next(Self, KeyGen))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Lock ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<VladGen, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, VladGen> for KeyGen {
    /// compile the script to check for errors
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, VladGen>, crate::error::Error> {
        let key = match key_gen("ephemeral", Some(Codec::Ed25519Priv), Some("".to_string()), (Some(1), Some(1))).await {
            Ok(v) => v,
            Err(e) => {
                context.error = Some(e);
                return Ok(Transition::next(Self, Failed));
            }
        };

        let mut vg = context.generated.take().unwrap();
        vg.key = key;
        context.generated = Some(vg);
        Ok(Transition::next(Self, Generate))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("KeyGen ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<VladGen, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, VladGen> for Generate {
    /// generate the Hash of the script
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, VladGen>, crate::error::Error> {
        let mut vg = context.generated.take().unwrap();
        vg.vlad = {
            match vlad::Builder::default()
                .with_signing_key(&vg.key.secret_keys[0])
                .with_cid(&vg.cid)
                .try_build() {
                Ok(v) => v,
                Err(e) => {
                    context.error = Some(Error::Multicid(e).into());
                    return Ok(Transition::next(Self, Failed));
                }
            }
        };
        context.generated = Some(vg);
        Ok(Transition::complete(Self))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Generate ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, context: &mut Context) -> Result<VladGen, crate::error::Error> {
        if context.generated.is_some() {
            Ok(context.generated.take().unwrap())
        } else {
            Err(Error::VladGenerationFailed.into())
        }
    }
}

#[async_trait::async_trait]
impl State<Context, VladGen> for Failed {
    /// ensure that we have the precoditions to succeed
    async fn next(self: Box<Self>, _context: &mut Context) -> Result<Transition<Context, VladGen>, crate::error::Error> {
        Ok(Transition::complete(Self))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Failed".to_string())
    }

    /// return the error
    async fn result(&self, context: &mut Context) -> Result<VladGen, crate::error::Error> {
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

    #[test]
    fn test_vladgen_ok() {
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
}
