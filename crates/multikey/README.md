[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
![](https://github.com/cryptidtech/multikey/actions/workflows/rust.yml/badge.svg)

# Multikey

A Rust implementation of the [multiformats][MULTIFORMATS] [multikey specification][MULTIKEY] and
[nonce specification][NONCE].

## Current Status

This implementation of the Multikey specification supports both public key and
secret key cryptography keys. For public key cryptography, it supports Ed25519,
Nist P256, P384, and P521, as well as BLS12-381 G1/G2 curves. For secret key
cryptography it supports ChaCha-256 keys.

This implementation supports encrypting/decrypting keys using ChaCha20-Poly1305
AEAD with keys derived with Bcrypt KDF from a preimage.

When using BLS12-381 keys, this implementations supports threshold key
splitting and combining as well as threshold signing and verifying.

This crate also supports converting to/from SSH format keys using the
[`ssh-key`][SSHKEY] crate. This gives full OpenSSH compatibility for reading in
OpenSSH serialized keys and converting them to Multikey format. This even
includes non-standard SSH key protocols such as secp256k1 and BLS12-381 G1/G2
keys through the use of [RFC 4251][RFC4251] standard for "additional algorithms"
names using the "@multikey" domain suffix. For instance, using this crate, an
secp256k1 Multikey converted to an SSH format key has the algorithm name
"secp256k1@multikey". A BLS12-381 G1 key share converted to SSH format has the
algorithm name "bls12_381-g1-share@multkey".

For the technical details of the design of Multikey or Nonce, please refer to
the specifications linked above.

## Introduction

This is a Rust implementation of a multicodec format for encryption keys. The 
design of the format is intentionally abstract to support any kind of
encryption key in any state (e.g. encrypted or unencrypted). This format should
be best thought of as a container of key material with abstract, algorithm-
specific views and a generic and self-describing data storage format.

Every piece of data in the serialized Multikey object either has a known-fixed
size or a self-describing variable size such that software processing these
objects do not need to support all encryption algorithms to be able to 
accurately calculate the size of the serialized object and skip over it if 
needed.

## Views on the Multikey Data 

To provide an abstract interface to encryption keys for all algorithms, this 
Multikey crate provides "views" on the Multikey data. These are read-only 
abstract interfaces to the Multikey attributes with implementations for 
different supporting encryption algorithms.

Currently the set of views provide generic access to the general attributes 
(`multikey::AttrView`) of the Multikey, the key data (`multikey::DataView`),
as well as views on the KDF attributes (`multikey::KdfAttrView`), and cipher
attributes (`multikey::CipherAttrView`) for encrypted Multikeys. For algorithms
that support threshold operations there is a threshold attributes view
(`multikey::ThresholdAttrView`).

For operations you can do with a Multikey, there is a cipher view
(`multikey::CipherView`) for encrypting/decrypting a Multikey, a conversion
view (`multikey::ConvView`) for converting the Multikey to other formats (e.g.
to/from ssh key format and secret keys to public keys), a fingerprint view
(`multikey::FingerprintView`) for getting a key fingerprint using a given
hashing codec, a KDF view (`multikey::KdfView`) for generating cipher keys for
use by a cipher view to encrypt/decrypt the Multikey, a threshold view
(`multikey::ThresholdView`) for key splitting and combining keys, and lastly a
sign view (`multikey::SignView`) and verify view (`multikey::VerifyView`) for
creating and verifying [`Multisig`][MULTISIG] digital signatures.

It is important to note that the operations that seem to mutate the Multikey 
(e.g. encrypt, decrypt, convert, etc) in fact do a copy-on-write (CoW)
operation and return a new Multikey with the mutation applied.

[CRYPTID]: https://cryptid.tech
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats
[MULTIKEY]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multikey.md
[NONCE]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/nonce.md
[SSHKEY]: https://crates.io/crates/ssh-key
[RFC4251]: https://www.rfc-editor.org/rfc/rfc4251.html#page-11
[MULTISIG]: https://github.com/cryptidtech/multisig
