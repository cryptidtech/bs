# BetterSign Architecture: Traits and Configuration Layers

## Overview

BetterSign implements a **layered trait architecture** that provides both maximum flexibility for custom implementations and convenience for the common case. This document explains the design philosophy and how to use each layer.

## Design Philosophy

**Core Principle**: Enable users to provide custom implementations with their own types, while providing a batteries-included reference implementation for rapid development.

## Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Layer 3: Application Code                              │
│  • Your wallet implementations                          │
│  • bs-wallets reference implementations                 │
│  • Integration code                                     │
│  Choice: Use config layer OR implement traits directly  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  Layer 2: Configuration Layer (bs::config)              │
│  • OPTIONAL convenience supertraits                     │
│  • Opinionated concrete types for reference impl        │
│  • Reduces boilerplate by ~80% for common cases         │
│  Types: Key, Codec, Multikey, Multisig                  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Generic Traits (bs-traits)                    │
│  • Pure generic traits with zero opinions               │
│  • Maximum flexibility - use ANY types you want         │
│  • No dependencies on concrete implementations          │
└─────────────────────────────────────────────────────────┘
```

## Layer 1: Generic Traits (bs-traits)

**Purpose**: Provide the most flexible trait definitions that work with ANY concrete types.

**When to use**: 
- You want complete control over types
- You're building a custom wallet with non-standard key formats
- You're integrating with existing cryptographic infrastructure
- You need types other than Multikey/Multisig

**Example - Custom Implementation**:
```rust
use bs_traits::{GetKey, Signer};
use bs_traits::sync::{SyncGetKey, SyncSigner};

struct MyHsmWallet {
    // Your custom HSM integration
}

// Implement with YOUR types
impl GetKey for MyHsmWallet {
    type Key = YourCustomPublicKey;      // Your type
    type KeyPath = YourCustomPath;        // Your type
    type Codec = YourCustomCodec;         // Your type
    type Error = YourCustomError;         // Your error
}

impl Signer for MyHsmWallet {
    type KeyPath = YourCustomPath;
    type Signature = YourCustomSignature; // Your signature format
    type Error = YourCustomError;
}

impl SyncSigner for MyHsmWallet {
    fn try_sign(&self, key: &Self::KeyPath, data: &[u8]) 
        -> Result<Self::Signature, Self::Error> 
    {
        // Your custom HSM signing logic
        todo!()
    }
}
```

**Trade-offs**:
- ✅ Maximum flexibility - any types you want
- ✅ Zero coupling to BetterSign's concrete types
- ⚠️ More verbose trait bounds in your code
- ⚠️ You'll need to implement your own `open_plog`/`update_plog` equivalents

## Layer 2: Configuration Layer (bs::config)

**Purpose**: Provide pre-configured supertraits with concrete types for the reference implementation.

**When to use**:
- You're happy with the reference types (Multikey, Multisig, etc.)
- You want rapid development with minimal boilerplate
- You're building a standard wallet implementation
- You want to use the provided `open_plog` and `update_plog` functions

**Concrete Types Used**:
- **Key paths**: `provenance_log::Key`
- **Codec**: `multicodec::Codec`
- **Public keys**: `multikey::Multikey`
- **Signatures**: `multisig::Multisig`

**Example - Using Config Layer**:

```rust
use bs::config::sync::{KeyManager, MultiSigner};

struct MyWallet {
    // Your wallet state using reference types
}

// Implement with concrete types already specified
impl KeyManager<MyError> for MyWallet {
    // Only need to specify Error type, everything else is fixed
    // Key = Multikey, KeyPath = Key, Codec = Codec
}

impl MultiSigner<MyError> for MyWallet {
    // Signature = Multisig, KeyPath = Key
}

// Much shorter trait bounds in your code:
fn use_wallet(wallet: &impl KeyManager<MyError>) {
    // vs the verbose bs_traits version
}
```

**Benefits**:
- ✅ Dramatically reduced boilerplate
- ✅ Works seamlessly with `open_plog`, `update_plog`, `BetterSign` struct
- ✅ Type safety enforced at compile time
- ✅ Clear, consistent types across the ecosystem

**Trade-offs**:
- ⚠️ Locked to reference types (Multikey, Multisig, Key, Codec)
- ⚠️ Not suitable if you need custom signature formats or key types

### Config Submodules

#### `bs::config::sync`
Synchronous trait supertraits:
- `KeyManager<E>`: Key management operations
- `MultiSigner<E>`: Signing and ephemeral key operations

#### `bs::config::asynchronous`
Asynchronous trait supertraits:
- `KeyManager<E>`: Async key management
- `MultiSigner<E>`: Async signing and ephemeral key operations

#### `bs::config::adapters`
Bridges between sync and async:
- `SyncToAsyncManager`: Adapts sync KeyManager to async
- `SyncToAsyncSigner`: Adapts sync MultiSigner to async

Used internally by `open_plog_sync` and `update_plog_sync`.

## Layer 3: Reference Operations (open_plog, update_plog)

**Design Decision**: The core operations `open_plog` and `update_plog` are **opinionated** and work with the config layer types.

**Why?** 
- Pragmatic: 95% of users will use the reference types
- Cleaner: Avoids excessive generic complexity
- Maintainable: Single code path to maintain

**For Users with Custom Types**:
You have two options:

### Option 1: Use the patterns, write your own operations
```rust
// Study the implementation of open_plog in crates/bs/src/ops/open.rs
// Adapt it to work with your custom types

pub async fn my_open_plog<E>(
    config: &Config,
    my_key_manager: &impl MyKeyManagerTrait,
    my_signer: &impl MySignerTrait,
) -> Result<Log, E> {
    // Your adapted implementation
}
```

### Option 2: Create adapters to the reference types
```rust
// Create adapters that convert your types to/from reference types
struct MyKeyAdapter {
    inner: MyCustomKeyManager,
}

impl bs::config::sync::KeyManager<E> for MyKeyAdapter {
    // Adapt your types to Multikey, Key, Codec
}
```

## Reference Implementation: bs-wallets

The `bs-wallets` crate provides reference implementations:

### `InMemoryKeyManager`

```rust
use bs_wallets::memory::InMemoryKeyManager;
use bs::config::sync::{KeyManager, MultiSigner};

// Generic over error type
let wallet = InMemoryKeyManager::<bs::Error>::new();

// Can be used with any error that meets the trait bounds
let wallet2 = InMemoryKeyManager::<bs_peer::Error>::new();

// Implements both config layer traits
fn test_wallet<E>(w: &impl KeyManager<E> + MultiSigner<E>) {
    // Works!
}
test_wallet(&wallet);
```

Key features:
- ✅ Implements `bs::config::sync::{KeyManager, MultiSigner}`
- ✅ Generic over error type
- ✅ Can be wrapped for async use via adapters
- ✅ Stores keys in memory with secure ephemeral key support

## Decision Matrix: Which Layer Should I Use?

| Scenario | Recommended Approach |
|----------|---------------------|
| Building a standard wallet | **Config Layer** (bs::config) |
| Using Multikey/Multisig | **Config Layer** (bs::config) |
| Want to use open_plog/update_plog directly | **Config Layer** (bs::config) |
| Integrating HSM or hardware wallet | **Generic Traits** (bs-traits) |
| Custom signature format (e.g., Ethereum) | **Generic Traits** (bs-traits) |
| Custom key derivation scheme | **Generic Traits** (bs-traits) |
| Need maximum flexibility | **Generic Traits** (bs-traits) |
| Prototyping quickly | **Config Layer** (bs::config) |

## FAQ

### Q: Can I mix and match layers?
**A**: Yes! You can use the generic traits for some components and the config layer for others. The adapters in `bs::config::adapters` help bridge between them.

### Q: Will using the config layer lock me in?
**A**: No. The config layer is just convenient type aliases and supertraits. You can always drop down to implementing `bs-traits` directly if your needs change.

### Q: Why not make open_plog/update_plog fully generic?
**A**: Pragmatism. It would add significant generic complexity for minimal benefit. 95% of users will use the reference types. Users with custom types can adapt the implementation (it's open source).

### Q: Can I contribute a new wallet implementation?
**A**: Yes! Add it to `bs-wallets` if it uses the reference types, or publish your own crate if it uses custom types. Both are supported patterns.

### Q: Is the config layer less flexible than using traits directly?
**A**: Yes, by design. It trades some flexibility for massive boilerplate reduction. Choose the right tool for your use case.

## Examples

See:
- `crates/bs-wallets/src/memory.rs` - Reference implementation using config layer
- `crates/interop-tests/src/bin/native.rs` - Integration example
- `crates/bs/src/better_sign.rs` - High-level API using config layer

## Summary

**BetterSign's trait architecture gives you choice**:
- **Rapid development**: Use the config layer with reference types
- **Maximum control**: Use bs-traits directly with your own types
- **Both**: Mix and match as needed

The key insight: **bs-traits remains generic and flexible** while **bs::config provides pragmatic defaults**. You're never locked in - pick the right tool for your use case.
