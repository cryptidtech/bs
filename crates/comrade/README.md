# Comrade

A flexible, extensible, and composable way to run provenance log scripts natively or in the browser.

## Overview

This crate is the main entry point for the Comrade library, which provides a framework for executing provenance log scripts in both native and browser environments. Comrade enables flexible script execution with support for lock and unlock operations through an intuitive key-value pair interface.

This crate is run during the "Verification" step of using a provenance log.

## Installation

This crate is typically used in the [../provenance-log/Cargo.toml](../provenance-log/) crate by adding this to the `Cargo.toml`:

```toml
[dependencies]
comrade.workspace = true
```

## Features

- Execute text-based provenance log scripts in native Rust or browser environments
- Flexible key-value pair interface for script data management
- Support for lock and unlock script operations
- Wasm component model compatibility

## Use 

The main API aims to be as simple as possible, and the following example shows how to use the Comrade library to run a script:

```rust
use comrade::Comrade;
use comrade_reference::{Pairs, Value};
use std::collections::HashMap;

#[derive(Clone, Default, Debug)]
struct TestData(HashMap<String, Value>);

impl Pairs for TestData {
    fn get(&self, key: &str) -> Option<Value> {
        self.0.get(key).cloned()
    }

    fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
        self.0.insert(key.to_string(), value.clone())
    }
}

// The message to sign, in both the lock and unlock scripts
let entry_key = "/entry/";
let entry_data = b"for great justice, move every zig!";

// The proof data that is provided by the unlock script
let proof_key = "/entry/proof";
let proof_data = hex::decode("b92483a6c006000100404819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03").unwrap();

// The public key to that must be proven by unlock scripts
let pubkey = "/pubkey";
let pub_key = hex::decode("ba24ed010874657374206b657901012054d94d7b8a11d6581af4a14bc6451c7a23049018610f108c996968fe8fce9464").unwrap();

// Our Key-Value Pairs
let mut kvp_unlock = TestData::default();
let mut kvp_lock = TestData::default();

// "/entry/" needs to be present on both lock and unlock stacks,
// since they are used in both the unlock and lock scripts:
// ie. push("/entry/") and check_signature("/pubkey", "/entry/")
kvp_unlock.put(entry_key, &entry_data.to_vec().into());
kvp_lock.put(entry_key, &entry_data.to_vec().into());

// "/entry/proof" only needs to be present on the unlock stack,
// since that's where the proof is used
kvp_unlock.put(proof_key, &proof_data.clone().into());

// "/pubkey" needs to be present on lock stack, to set what the PubKey is
kvp_lock.put(pubkey, &pub_key.into());

let unlock_script = format!(
    r#"
        // push the serialized Entry as the message
        push("{entry_key}"); 

        // push the proof data
        push("{proof_key}");
    "#
);

let first_lock = format!(
    r#"
        // check the first key, which is ephemeral
        check_signature("/ephemeral", "{entry_key}") 
    "#
);

let other_lock_script = format!(
    r#"
        // then check a possible threshold sig...
        check_signature("/recoverykey", "{entry_key}") ||

        // then check a possible pubkey sig...
        check_signature("/pubkey", "{entry_key}") ||
        
        // then the pre-image proof...
        check_preimage("/hash")
    "#
);

let mut comrade = Comrade::new(&kvp_lock, &kvp_unlock)
    .try_unlock(&unlock_script)
    .expect("Failed to unlock comrade");

// check the lock scripts
let locks = [first_lock, other_lock_script];

// check the locks
let mut count = 0;
for lock in locks {
    if let Some(Value::Success(ct)) =
        comrade.try_lock(&lock).expect("Failed to lock comrade")
    {
        count = ct;
        break;
    }
}

// check the count
assert_eq!(count, 2);
```

## Tests 

To run the tests:

```sh 
# see http://just.systems/ for more details
just test
```

This will ensure the default component is built and available for the default wasm runtime.

## Architecture

Comrade is designed with a modular architecture that consists of:

1. **Core API**: The main `Comrade` struct provides a simple interface for script execution
2. **Reference Implementation**: The crate includes a reference implementation with default behaviors
3. **WASM Integration**: Support for WebAssembly components enables cross-platform compatibility

By default, Comrade uses a direct implementation in Rust. But, it is possible to break up the build into modular wasm components and compose them together. This is being left as an area for future work when demand arises.

### Wasm Component Layer

This reference implementation makes opinions about what dependencies to use and which wasm runtime to use to run the components, but it should be noted that it is possible to swap in your own runtime for both the component and the wasm runtime. 

 But, for example, `wasm_component_layer` crate gives us an isomorphic way to load components in native or the browser directly from Rust. We use a patch until [this dependency fix lands](https://github.com/DouglasDwyer/wasm_component_layer/pull/26). 

## Related Crates

- `comrade_reference`: Provides the reference implementation for Comrade, which can be used directly in Comrade, or bundled into a wasm component.
- `wasmi_runtime`: Native runtime for WebAssembly components
- `js_wasm_runtime_layer`: Browser runtime for WebAssembly components

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

FSL-1.1
