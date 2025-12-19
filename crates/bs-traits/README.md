[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]

# BS-Traits

**Generic trait definitions for BetterSign - the foundation for maximum flexibility.**

## Purpose

This crate provides pure, generic trait definitions that enable custom implementations with **any concrete types you choose**. It is intentionally free of opinions about specific cryptographic implementations.

## When to Use

**Use this crate directly when:**
- You need custom key types (e.g., HSM integration, hardware wallets)
- You want custom signature formats (e.g., Ethereum, Bitcoin-specific formats)
- You're integrating with existing cryptographic infrastructure
- You need maximum flexibility and control

**Use `bs::config` instead when:**
- You're building a standard wallet with Multikey/Multisig
- You want rapid development with minimal boilerplate
- You want to use the reference `open_plog` and `update_plog` functions

## Architecture

BS-Traits is **Layer 1** in BetterSign's three-layer architecture:

```
Layer 3: Application Code (your implementations)
           ↓
Layer 2: Configuration Layer (bs::config - optional convenience)
           ↓
Layer 1: Generic Traits (bs-traits - maximum flexibility) ← YOU ARE HERE
```

See [ARCHITECTURE.md](../../docs/ARCHITECTURE.md) for complete documentation.

## Trait Categories

### Core Traits
- `Signer` / `Verifier` - Cryptographic signing and verification
- `Encryptor` / `Decryptor` - Encryption operations
- `GetKey` / `KeyDetails` - Key management
- `SecretSplitter` / `SecretCombiner` - Secret sharing schemes

### Async Traits (`bs_traits::asyncro`)
- `AsyncSigner`, `AsyncVerifier`
- `AsyncEncryptor`, `AsyncDecryptor`
- `AsyncKeyManager`, `AsyncMultiSigner`
- All async operations return `BoxFuture` for dyn compatibility

### Sync Traits (`bs_traits::sync`)
- `SyncSigner`, `SyncVerifier`
- `SyncEncryptor`, `SyncDecryptor`
- `SyncGetKey`, `SyncPrepareEphemeralSigning`

## Example: Custom Implementation

```rust
use bs_traits::{GetKey, Signer};
use bs_traits::sync::{SyncGetKey, SyncSigner};

struct MyHsmWallet {
    // Your custom HSM integration
}

// Use YOUR types
impl GetKey for MyHsmWallet {
    type Key = YourPublicKeyType;
    type KeyPath = YourPathType;
    type Codec = YourCodecType;
    type Error = YourError;
}

impl Signer for MyHsmWallet {
    type KeyPath = YourPathType;
    type Signature = YourSignatureType;  // Not limited to Multisig!
    type Error = YourError;
}

impl SyncSigner for MyHsmWallet {
    fn try_sign(&self, key: &Self::KeyPath, data: &[u8]) 
        -> Result<Self::Signature, Self::Error> 
    {
        // Your custom signing logic
    }
}
```

## Comparison with bs::config

| Aspect | bs-traits (this crate) | bs::config |
|--------|----------------------|------------|
| Flexibility | Maximum - any types | Fixed types |
| Boilerplate | More verbose | Minimal |
| Types | Your choice | Multikey, Multisig, etc. |
| Use with open_plog | Need custom implementation | Direct use |
| Best for | Custom integrations | Standard wallets |

## Features

- `dyn-compatible` (default): Ensures traits can be used as `dyn Trait` objects

## License

Functional Source License 1.1

[CRYPTID]: https://cryptid.tech
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications