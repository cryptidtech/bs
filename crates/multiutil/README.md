[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
![](https://github.com/cryptidtech/multiutil/actions/workflows/rust.yml/badge.svg)

# Multiutil

Helpful traits, types, and functions for constructing multiformat types.

## BaseEncoded

The `BaseEncoded` "smart pointer" wraps any multiformat type that implements
the `EncodingInfo` trait also found in this crate. `BaseEncoding` automatically
handles base encoding the inner value using the [Multibase][MULTIBASE] text
encoding systems.

## CodecInfo

The `CodecInfo` trait allows a multiformat type to expose its
[Multicodec][MULTICODEC] value to code that relies on this trait.

## Varuint

This is an implementation of a [variable length, unsigned integer][VARUINT]
that is common to all multiformat protocols and types.

## Varbytes

This is the combination of a `Varuint` followed by a binary octet array of
equal length. This is a common way to encode arbitrary binary data so that any
code can skip over the data if it doesn't know how, nor want, to process it

```
<varbytes> ::= <varuint> N(OCTET)
                   ^        ^
                  /          \
          count of            variable number
            octets            of octets
```

[CRYPTID]: https://cryptid.tech/
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats/
[MULTIBASE]: https://github.com/multiformats/multibase
[VARUINT]: https://github.com/multiformats/unsigned-varint
