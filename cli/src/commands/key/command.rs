// SPDX-License-Identifier: FSL-1.1
//
//use std::path::PathBuf;
use structopt::StructOpt;

/// The "key" cli sub-command
#[derive(Debug, StructOpt)]
pub enum KeyCommand {
    /*
    /// Set the default key
    #[structopt(name = "default")]
    Default {
        /// clear the default key
        #[structopt(long = "clear", short = "c", group = "default")]
        clear: bool,

        /// the name of the key to make default
        #[structopt(long = "set", short = "s", group = "default")]
        hash: Option<String>,
    },
    */

    /// Generate a new key
    #[structopt(name = "generate")]
    Generate {
        /// Key type, valid values: "eddsa", "es256k", "blsg1", "blsg2"
        #[structopt(long = "type", short = "t")]
        key_type: Option<String>,

        /// Comment for the keypair
        #[structopt(long = "comment", short = "C")]
        comment: Option<String>,

        /// Threshold for split keys
        #[structopt(long = "threshold", short = "T")]
        threshold: Option<usize>,

        /// Limit for split keys
        #[structopt(long = "limit", short = "L")]
        limit: Option<usize>,
    },

    /// List available keys
    #[structopt(name = "list")]
    List,

    /*
    /// Sign using the default/specified key
    #[structopt(name = "sign")]
    Sign {
        /// The hash of the key to sign with
        #[structopt(long = "keyhash", short = "h")]
        keyhash: Option<String>,

        /// Message encoding codec
        #[structopt(long = "encoding", short = "e")]
        encoding: Option<String>,

        /// Combined signature
        #[structopt(long = "combined", short = "c")]
        combined: Option<bool>,

        /// File to write the signature to, or stdout if missing
        #[structopt(long = "sig", short = "s", parse(from_os_str))]
        signature: Option<PathBuf>,

        /// Message to sign
        #[structopt(parse(from_os_str))]
        msg: Option<PathBuf>,
    },

    /// Verify using the default/specified key
    Verify {
        /// The hash of the key to verify with
        #[structopt(long = "keyhash", short = "h")]
        keyhash: Option<String>,

        /// Signature file to read signture from
        #[structopt(long = "sig", short = "s", parse(from_os_str))]
        signature: PathBuf,

        /// Message that was signed
        #[structopt(parse(from_os_str))]
        msg: Option<PathBuf>,
    }, /*
       /// Remove a key
       #[structopt(name = "remove")]
       Remove {
           /// the name of the key to remove
           name: String,
       },
       */
    */
}

/// async entry point for all key commands
pub async fn cmd(cmd: &KeyCommand) -> Result<(), crate::error::Error> {
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

/// convenience function that hides all of the details
pub async fn gen(
    purpose: &str,
    codec: Option<Codec>,
    comment: Option<String>,
    threshold: (Option<usize>, Option<usize>)) -> Result<KeyEntry, crate::error::Error> {

    let mut ctx = Context::new(purpose, codec, comment, threshold);
    crate::commands::run_to_completion(Initial, &mut ctx).await
}


