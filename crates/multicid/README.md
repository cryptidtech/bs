[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
![](https://github.com/cryptidtech/multicid/actions/workflows/rust.yml/badge.svg)

# Multicid

A Rust implementation of the [multiformats][MULTIFORMATS] [content identifier (CID)][CID]
and [very long-lived addresses (VLADs)][VLAD] specifications.

## Current Status

This crate supports the full CIDv0 and CIDv1 [specification][CID] as used in
IPFS and the VLAD [specification][VLAD] used in provenance log based applications.
For technical details on either, please refer to their respective
specifications linked above.

### What are VLADs?

A VLAD is intended to replace public keys as identifiers in distributed systems
by combinind a random nonce (i.e. number used once) and a CID for a WASM
verification script designed to run in an implementation of the web assembly
cryptographic constructs [WACC VM][WACC]. The nonce in the Vlad can be random but in
some use cases the bytes inside the nonce are a [Multisig][MULTISIG] digital signature
over the CID part of the VLAD. Digital signatures are random enough to serve
the purposes of making the VLAD unique while also cryptographically linking the
VLAD to the key pair used to create the VLAD. This is a critical security
feature for linking VLADs to provenance logs.

Briefly, the reasons why distributed systems should use VLADs instead of public
key identifiers is because key material is subject to compromise and rotation.
Distributed systems that rely on public key identifiers (e.g. web-of-trust, all
other decentralized identity systems) are brittle and the resulting distributed
system does not meet the preconditions for a metastable network to emerge.
Whenever keys change, the links between the nodes break. Public keys are
typically used because they are random enough to number a seemingly infinite
number of things without running out and they are also a cryptographic
commitment to a validation function that can be used to verify the data they
are identifying. VLADs have both of these properties but are not derived from
key material and are therefore not subject to compromise or rotation. That
makes them much more resilient and stable distributed system links over long
spans of time.

[CRYPTID]: https://cryptid.tech/
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats/
[CID]: https://docs.ipfs.tech/concepts/content-addressing/
[VLAD]: https://github.com/cryptidtech/blob/main/specifications/vlad.md
[WACC]: https://github.com/cryptidtech/wacc/
[MULTISIG]: https://github.com/cryptidtech/multisig/
