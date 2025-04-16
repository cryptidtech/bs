[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
![](https://github.com/cryptidtech/multihash/actions/workflows/rust.yml/badge.svg)

# Multihash

Multiformats [Multihash][MULTIHASH] implementation without constant size in the
type signature.

## Features

* Uses the [`multiutil::BaseEncoded`] smart pointers to wrap the Multihash into
  EncodecMultihash for base encoded multihashes; automating the
  encoding/decoding to/from strings and byte slices. 
* Serde support to/from human readable and binary formats.
* Supports raw binary encoding and decoding using [`Into<Vec<u8>>`] and
  [`TryFrom<&[u8]>`] trait implementations.

## Examples

Bulding a multihash from some bytes:

```rust
let mh = Builder::new_from_bytes(Codec::Sha3384, b"for great justice, move every zig!")?
    .try_build()?;
```

Building a base encoded multihash from some bytes:

```rust
let encoded_mh = Builder::new_from_bytes(Codec::Sha3256, b"for great justice, move every zig!")?
    .with_base_encoding(Base::Base58Btc)
    .try_build_encoded()?;
```

Existing multihash objects can be converted to [`crate::mh::EncodedMultihash`]
objects by using `.into()`:

```rust
let mh = Builder::new_from_bytes(Codec::Sha3384, b"for great justice, move every zig!")?
    .try_build()?;

// this will use the preferred encoding for multihash objects: Base::Base16Lower
let encoded_mh1: EncodedMultihash = mh.into();

// or you can chose the base enccoding...
let encoded_mh2: EncodedMultihash::new(Base::Base32Upper, mh);
```

[CRYPTID]: https://cryptid.tech/
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats/
[MULTIHASH]: https://www.multiformats.io/multihash/
