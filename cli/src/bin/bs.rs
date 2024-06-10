// SPDX-License-Identifier: FSL-1.1
#![allow(dead_code)]
//mod commands;

//use best_practices::cli::io::{reader, writer};
use bs::prelude::*;
//use commands::prelude::*;
//use log::debug;
//use multicodec::Codec;
//use multihash::EncodedMultihash;
//use multikey::{mk, EncodedMultikey, Views};
//use multisig::{EncodedMultisig, Multisig};
//use multiutil::{prelude::Base, CodecInfo};
//use std::{convert::TryFrom, fs::File, io::Read, path::PathBuf};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "bs",
    version = "0.1.1",
    author = "Dave Huseby <dwh@linuxprogrammer.org>",
    about = "BetterSign provenance log tool"
)]
struct Opt {
    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    quiet: bool,

    /// Verbosity (-v, -vv, -vvv)
    #[structopt(short = "v", parse(from_occurrences))]
    verbosity: usize,

    /// Config file to use
    #[structopt(long = "config", short = "c", parse(from_os_str))]
    config: Option<PathBuf>,

    /// Keychain file
    #[structopt(long = "keychain", short = "k", parse(from_os_str))]
    keyfile: Option<PathBuf>,

    /// Data dir to use
    #[structopt(long = "data", short = "d", parse(from_os_str))]
    data: Option<PathBuf>,

    /// Use an ssh-agent?
    #[structopt(long = "ssh-agent", short = "s")]
    sshagent: bool,

    /// Ssh-agent env var
    #[structopt(long = "ssh-agent-env", default_value = "SSH_AUTH_SOCK")]
    sshagentenv: String,

    /// Subcommand
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    /*
    /// Key operations
    #[structopt(name = "key")]
    Key {
        /// Key subcommand
        #[structopt(subcommand)]
        cmd: KeyCommand,
    },
    /// Provenance log operations
    #[structopt(name = "plog")]
    Plog {
        /// Provenance log subcommand
        #[structopt(subcommand)]
        cmd: PlogCommand
    }
    */
}

/*
#[derive(Debug, StructOpt)]
enum PlogCommand {
    /// Generate a new key
    #[structopt(name = "generate")]
    Generate, 
}
*/

#[tokio::main]
async fn main() -> Result<(), Error> {
    // parse the cli options
    let _opt = Opt::from_args();

    /*
    // set up the logger
    stderrlog::new()
        .quiet(opt.quiet)
        .verbosity(opt.verbosity)
        .init()
        .map_err(|e| bs::Error::Log(e))?;
    */

    /*
    match opt.cmd {
        Command::Key { cmd } => {
            match cmd {
                /*
                KeyCommand::Default { clear, hash } => {
                    let mut config =
                        Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;

                    if clear {
                        config.set_default_key(None)?;
                    } else if let Some(hash) = hash {
                        config.set_default_key(Some(hash))?;
                    }

                    if let Ok(key) = config.default_key() {
                        let kh = {
                            let fv = key.fingerprint_view()?;
                            EncodedMultihash::new(Base::Base58Btc, fv.fingerprint(Codec::Blake2S256)?)
                        };
                        println!("{} {} {}", key.codec(), kh, key.comment,);
                    } else {
                        println!("No default key set");
                    }
                }
                */
                KeyCommand::Generate { key_type, comment, threshold, limit } => {
                    // get the key codec
                    let codec = match key_type {
                        Some(kt) => {
                            Some(match kt.to_lowercase().as_str() {
                                "eddsa" => Codec::Ed25519Priv,
                                "es256k" => Codec::Secp256K1Priv,
                                "blsg1" => Codec::Bls12381G1Priv,
                                "blsg2" => Codec::Bls12381G2Priv,
                                _ => return Err(Error::InvalidKeyType(kt)),
                            })
                        }
                        None => None
                    };

                    // generate the new key
                    let gk = key::gen("a new key", codec, comment, (threshold, limit)).await?;

                    // get the config
                    let mut config =
                        Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;

                    // add the key to the keychain
                    config.keychain()?.borrow_mut().add(&gk)?;
                }
                KeyCommand::List => {
                    // load the config
                    let mut config =
                        Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;
                    let keys = config.keychain()?.borrow().list()?;
                    for key in &keys {
                        println!("{}", key);
                    }
                }
                /*
                Command::Sign {
                    keyhash,
                    encoding,
                    combined,
                    signature,
                    msg,
                } => {
                    // load the config
                    let mut config =
                        Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;

                    // look up the signing key by hash
                    let keyhash = match keyhash {
                        Some(h) => EncodedMultihash::try_from(h.as_str())?,
                        None => config.default_key_fingerprint()?,
                    };
                    debug!("keyhash: {:?}", keyhash);
                    let encoding = encoding.unwrap_or("identity".to_string());
                    let encoding = Codec::try_from(encoding.as_str())?;
                    let key = config.keychain()?.borrow().get(&keyhash)?;
                    let emk: EncodedMultikey = key.clone().into();
                    debug!("signing key: {:?}", emk);

                    // read the msg from either the file or stdin
                    let mut r = reader(&msg)?;
                    let mut m = Vec::default();
                    r.read_to_end(&mut m)?;

                    // determine if this is a combined signature
                    let combined = combined.unwrap_or_default();

                    // generate multisig
                    let ms = config
                        .keychain()?
                        .borrow_mut()
                        .sign(&key, combined, encoding, &m)?;
                    let ems: EncodedMultisig = ms.clone().into();
                    debug!("signature: {:?}", ems);
                    let out: Vec<u8> = ms.into();

                    let mut w = writer(&signature)?;
                    w.write_all(&out)?;
                    println!("signed!");
                }
                */
                /*
                Command::Verify {
                    keyhash,
                    signature,
                    msg,
                } => {
                    // load the config
                    let mut config =
                        Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;

                    // look up the signing key by hash
                    let keyhash = match keyhash {
                        Some(h) => EncodedMultihash::try_from(h.as_str())?,
                        None => config.default_key_fingerprint()?,
                    };
                    debug!("keyhash: {:?}", keyhash);
                    let key = config.keychain()?.borrow().get(&keyhash)?;
                    let emk: EncodedMultikey = key.clone().into();
                    debug!("verifying key: {:?}", emk);

                    // read the signature data from file
                    let ms = {
                        let mut r = File::open(&signature)?;
                        let mut s = Vec::default();
                        r.read_to_end(&mut s)?;
                        Multisig::try_from(s.as_slice())?
                    };
                    let ems: EncodedMultisig = ms.clone().into();
                    debug!("signature: {:?}", ems);

                    // get the message
                    let m = if ms.message.is_empty() {
                        // read the msg from either the file of stdin
                        let mut r = reader(&msg)?;
                        let mut m = Vec::default();
                        r.read_to_end(&mut m)?;
                        m
                    } else {
                        ms.message.clone()
                    };

                    // verify multisig
                    let vv = key.verify_view()?;
                    vv.verify(&ms, Some(m.as_slice()))?;
                    println!("signature valid!");
                }
                */
                /*
                Command::Remove { name } => {
                    let mut config =
                        Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;
                    let mut keychain = config.keychain()?;
                    let key = config.default_key()?;
                    if key.comment().to_string() == name {
                        config.set_default_key(None)?;
                        keychain.
                    }
                }
                */
            }
        }
        /*
        Command::Plog { cmd } => {
            match cmd {
                PlogCommand::Generate => {
                    // generate the new key
                    let plog = plog::gen("for fun").await?;
                    println!("{:?}", plog);
                }
            }
        }
        */
    }
    */

    Ok(())
}
