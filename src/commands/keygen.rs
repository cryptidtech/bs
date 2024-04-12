// SPDX-License-Identifier: FSL-1.1
use crate::{keychain::KeyEntry, commands::{State, Terminal, Transition, TransitionFrom}};
use log::debug;
use multibase::Base;
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{KEY_CODECS, Views};
use std::io::{self, BufRead};

/// convenience function that hides all of the details
pub async fn key_gen(
    purpose: &str,
    codec: Option<Codec>,
    comment: Option<String>,
    threshold: (Option<usize>, Option<usize>)) -> Result<KeyEntry, crate::error::Error> {

    let mut ctx = Context::new(purpose, codec, comment, threshold);
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
    #[error("key generation failed")]
    KeyGenerationFailed,
}

// the states
states!(Initial, CodecAsk, CommentAsk, ThresholdAsk, [Generate], [Failed]);

// the happy path
path!(Initial -> CodecAsk -> CommentAsk -> ThresholdAsk -> Generate);

// We can skip CodecAsk, CodecAsk + CommentAsk, and CodecAsk + CommentAsk + ThresholdAsk
paths!(Initial -> CommentAsk, ThresholdAsk, Generate);

// From CodecAsk we can skip CommentAsk, CommentAsk + ThresholdAsk 
paths!(CodecAsk -> ThresholdAsk, Generate);

// from CommentAsk we can skip ThresholAsk
path!(CommentAsk -> Generate);

// all of the Failed paths
failures!(CodecAsk, CommentAsk, ThresholdAsk, Generate -> Failed);

/// tracks the current state of the wasm loader
#[derive(Clone, Default)]
pub struct Context {
    // inputs
    purpose: String,
    codec: Option<Codec>,
    comment: Option<String>,
    threshold: (Option<usize>, Option<usize>),
    // outputs
    generated: Option<KeyEntry>,
    error: Option<Error>,
}

impl Context {
    /// contruct a new context for the key generator
    pub fn new(purpose: &str, codec: Option<Codec>, comment: Option<String>, threshold: (Option<usize>, Option<usize>)) -> Self  {
        Self {
            purpose: purpose.to_string(),
            codec,
            comment,
            threshold,
            .. Default::default()
        }
    }
}

#[async_trait::async_trait]
impl State<Context, KeyEntry> for Initial {
    /// ensure that we have the precoditions to succeed
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, KeyEntry>, crate::error::Error> {
        // output what we're doing
        println!("Generating {}", &context.purpose);
        if context.codec.is_none() || !KEY_CODECS.contains(&context.codec.clone().unwrap()) {
            Ok(Transition::next(Self, CodecAsk))
        } else if context.threshold.1.is_none() {
            Ok(Transition::next(Self, ThresholdAsk))
        } else {
            Ok(Transition::next(Self, Generate))
        }
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Initial ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<KeyEntry, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, KeyEntry> for CodecAsk {
    /// ask for the codec
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, KeyEntry>, crate::error::Error> {

        // loop getting the key type from the user
        let stdin = io::stdin();
        loop {
            println!("Which key type, default is 'eddsa'? ('eddsa', 'es256k', 'blsg1', 'blsg2'):");
            let key_type = {
                let mut kt = String::default();
                match stdin.lock().read_line(&mut kt) {
                    Ok(len) if len == 1 => "eddsa".to_string(),
                    Ok(len) if len > 1 => kt.trim().to_lowercase(),
                    Ok(_) => "eddsa".to_string(),
                    Err(_) => {
                        context.error = Some(Error::NoCodec);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };
            debug!("key_type = {}", key_type);

            // figure out the codec
            let codec = match key_type.as_str() {
                "eddsa" => Codec::Ed25519Priv,
                "es256k" => Codec::Secp256K1Priv,
                "blsg1" => Codec::Bls12381G1Priv,
                "blsg2" => Codec::Bls12381G2Priv,
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

        if context.comment.is_none() {
            Ok(Transition::next(Self, CommentAsk))
        } else if context.threshold.1.is_none() && 
            (context.codec.clone().unwrap() == Codec::Bls12381G1Priv ||
             context.codec.clone().unwrap() == Codec::Bls12381G2Priv) {
            // only ask for threshold details if the codec supports it and the threshold hasn't
            // been supplied
            Ok(Transition::next(Self, ThresholdAsk))
        } else {
            Ok(Transition::next(Self, Generate))
        }
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("CodecAsk ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<KeyEntry, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, KeyEntry> for CommentAsk {
    /// ask for the codec
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, KeyEntry>, crate::error::Error> {

        // loop getting the key type from the user
        let stdin = io::stdin();
        loop {
            println!("Would you like to add a comment, default is ''?:");
            let comment = {
                let mut c = String::default();
                match stdin.lock().read_line(&mut c) {
                    Ok(len) if len == 1 => String::default(),
                    Ok(len) if len > 1 => c.trim().to_string(),
                    Ok(_) => String::default(),
                    Err(_) => {
                        context.error = Some(Error::NoComment);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };

            context.comment = Some(comment);
            break;
        }

        if (context.threshold.0.is_none() && context.threshold.1.is_none()) &&
            (context.codec.clone().unwrap() == Codec::Bls12381G1Priv ||
             context.codec.clone().unwrap() == Codec::Bls12381G2Priv) {
            debug!("going to ask for threshold information");
            // only ask for threshold details if the codec supports it and the threshold hasn't
            // been supplied
            Ok(Transition::next(Self, ThresholdAsk))
        } else {
            debug!("heading to the generate step");
            Ok(Transition::next(Self, Generate))
        }
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("CodecAsk ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<KeyEntry, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, KeyEntry> for ThresholdAsk {
    /// compile the script to check for errors
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, KeyEntry>, crate::error::Error> {
        let stdin = io::stdin();
        loop {
            let doit = loop {
                println!("Would you like to create a threshold group, default is 'N'? ('Y', 'N'):");
                let mut yn = String::default();
                match stdin.lock().read_line(&mut yn) {
                    Ok(len) if len == 1 => break false,
                    Ok(len) if len == 2 => match yn.trim().to_lowercase().as_str() {
                        "y" => break true,
                        "n" => break false,
                        _ => continue,
                    }
                    Ok(len) if len > 1 => continue,
                    Ok(_) => continue,
                    Err(_) => {
                        context.error = Some(Error::NoAnswer);
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };

            if doit {
                let limit = loop {
                    println!("How many shares, default is '1'?:");
                    let mut num = String::default();
                    match stdin.lock().read_line(&mut num) {
                        Ok(len) if len == 1 => break 1,
                        Ok(len) if len > 1 => match num.trim().to_string().parse::<usize>() {
                            Ok(n) if n == 0 => continue,
                            Ok(n) if n > 0 => break n,
                            Ok(_) => continue,
                            Err(_) => continue,
                        }
                        Ok(_) => break 1,
                        Err(_) => {
                            context.error = Some(Error::NoAnswer);
                            return Ok(Transition::next(Self, Failed));
                        }
                    }
                };

                let threshold = loop {
                    println!("How many shares needed to reconstruct, default is '1'?:");
                    let mut num = String::default();
                    match stdin.lock().read_line(&mut num) {
                        Ok(len) if len == 1 => break 1,
                        Ok(len) if len > 1 => match num.trim().to_string().parse::<usize>() {
                            Ok(n) if n == 0 => continue,
                            Ok(n) if n > 0 && n > limit => continue,
                            Ok(n) if n > 0 && n <= limit => break n,
                            Ok(_) => continue,
                            Err(_) => continue,
                        }
                        Ok(_) => break 1,
                        Err(_) => {
                            context.error = Some(Error::NoAnswer);
                            return Ok(Transition::next(Self, Failed));
                        }
                    }
                };

                context.threshold = (Some(threshold), Some(limit));
            }
            break;
        }
        Ok(Transition::next(Self, Generate))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("ThresholdAsk ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, _context: &mut Context) -> Result<KeyEntry, crate::error::Error> {
        Err(Error::NoResult.into())
    }
}

#[async_trait::async_trait]
impl State<Context, KeyEntry> for Generate {
    /// generate the Hash of the script
    async fn next(self: Box<Self>, context: &mut Context) -> Result<Transition<Context, KeyEntry>, crate::error::Error> {
        // get the parameters
        let codec = context.codec.take().unwrap();
        let comment = context.comment.take().unwrap();
        let threshold = context.threshold.0.take().unwrap_or(1);
        let limit = context.threshold.1.take().unwrap_or(1);

        // build the key
        let mut rng = rand::rngs::OsRng::default();
        let mk = {
            // create the builder
            let builder = match multikey::Builder::new_from_random_bytes(codec, &mut rng) {
                Ok(v) => v,
                Err(e) => {
                    context.error = Some(e.into());
                    return Ok(Transition::next(Self, Failed));
                }
            };
            // build the key
            match builder.with_comment(&comment).try_build() {
                Ok(v) => v,
                Err(e) => {
                    context.error = Some(e.into());
                    return Ok(Transition::next(Self, Failed));
                }
            }
        };

        // get the public key and its fingerprint
        let (pubkey, fingerprint) = {
            let pk = {
                // get the conversion view
                let cv = match mk.conv_view() {
                    Ok(v) => v,
                    Err(e) => {
                        context.error = Some(e.into());
                        return Ok(Transition::next(Self, Failed));
                    }
                };
                // convert to the public key
                match cv.to_public_key() {
                    Ok(v) => v,
                    Err(e) => {
                        context.error = Some(e.into());
                        return Ok(Transition::next(Self, Failed));
                    }
                }
            };

            let kh = {
                // get the fingerprint view
                let fv = match pk.fingerprint_view() {
                    Ok(v) => v,
                    Err(e) => {
                        context.error = Some(e.into());
                        return Ok(Transition::next(Self, Failed));
                    }
                };
                // get the fingerprint
                let fp = match fv.fingerprint(Codec::Sha3256) {
                    Ok(v) => v,
                    Err(e) => {
                        context.error = Some(e.into());
                        return Ok(Transition::next(Self, Failed));
                    }
                };
                // get the encoded fingerprint
                EncodedMultihash::new(Base::Base32Lower, fp)
            };

            (pk, kh)
        };

        // store the output
        let mut gk = KeyEntry {
            fingerprint: Some(fingerprint),
            pubkey,
            threshold,
            .. Default::default()
        };
         
        // do the threshold operation if needed
        if limit > 1 {
            // get the threshold view
            let tv = match mk.threshold_view() {
                Ok(v) => v,
                Err(e) => {
                    context.error = Some(e.into());
                    return Ok(Transition::next(Self, Failed));
                }
            };

            // split the key
            let mut keys = match tv.split(threshold, limit) {
                Ok(v) => v,
                Err(e) => {
                    context.error = Some(e.into());
                    return Ok(Transition::next(Self, Failed));
                }
            };

            // store the secret key shares
            gk.secret_keys.append(&mut keys);
        } else {
            // store the secret key
            gk.secret_keys.push(mk);
        }

        context.generated = Some(gk);
        Ok(Transition::complete(Self))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Generate ==> ".to_string())
    }

    /// Get the result of this state if it is a terminal one
    async fn result(&self, context: &mut Context) -> Result<KeyEntry, crate::error::Error> {
        if context.generated.is_some() {
            Ok(context.generated.take().unwrap())
        } else {
            Err(Error::KeyGenerationFailed.into())
        }
    }
}

#[async_trait::async_trait]
impl State<Context, KeyEntry> for Failed {
    /// ensure that we have the precoditions to succeed
    async fn next(self: Box<Self>, _context: &mut Context) -> Result<Transition<Context, KeyEntry>, crate::error::Error> {
        Ok(Transition::complete(Self))
    }

    /// return the status
    async fn status(&self, _context: &mut Context) -> Result<String, crate::error::Error> {
        Ok("Failed".to_string())
    }

    /// return the error
    async fn result(&self, context: &mut Context) -> Result<KeyEntry, crate::error::Error> {
        Err(context.error.take().ok_or::<crate::error::Error>(Error::NoError.into())?.clone().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::run_to_completion;

    macro_rules! bo {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_key_gen_ok() {
        for codec in KEY_CODECS {
            let mut ctx = Context::new("test key", Some(codec), Some("test".to_string()), (Some(1), Some(1)));
            let ret = bo!(run_to_completion(Initial, &mut ctx));
            assert!(ret.is_ok());

            let ke = ret.unwrap();
            println!("{}", ke);
        }
    }
    
    #[test]
    fn test_convenience_fn() {
        for codec in KEY_CODECS {
            let ret = bo!(key_gen("test key", Some(codec), Some("test".to_string()), (Some(1), Some(1))));
            assert!(ret.is_ok());
        }
    }
}
