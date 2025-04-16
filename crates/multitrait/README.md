[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
![](https://github.com/cryptidtech/multitrait/actions/workflows/rust.yml/badge.svg)

# Multitrait

This crate contains three helpful traits common to most/all multiformats
objects:

**`EncodeInto`**
: Defines a single function for encoding a value into a `Vec<u8>`

**`TryDecodeFrom`**
: Defines a simple interface for fallibly decoding a value from a `&[u8]` while
  tracking which bytes have been consumed.

**`Null`**
: Defines two functions for creating a "null" multiformats value and for
  testing if a multiformats value is the null value. This allows for the 
  definition of a "null" CID or a "null" VLAD or even a "null" Multisig.

[CRYPTID]: https://cryptid.tech/
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats/
