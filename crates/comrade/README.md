# Comrade

A flexible, extensible, and composable way to run provenance log scripts natively or in the browser.

This crate is the main entry point for the library. 


## Use 

The main API aims to be super simple:

```ignore
let unlocked = Comrade::new(kvp_lock, kvp_unlock)
  .try_unlock(&unlock)?;

let mut count = 0;

for lock in locks {
  if let Some(Value::Success(ct)) = unlocked.try_lock(lock)? {
    count = ct;
    break;
  }
}
```

## Tests 

To run the test:

```sh 
# see http://just.systems/ fr more details
just test
```

This will ensure the default component is built and available for the default wasm runtime.

## Wasm Component Layer

This reference implementation makes opinions about what dependencies to use, and which wasm runtime to use to run the components, but it should be noted that you can swap in your own runtime for both the component and the wasm runtime. 

`wasm_component_layer` crate gives us an isomorphic way to load components in native or the browser directly from Rust. We use a patch until [this dependency fix lands](https://github.com/DouglasDwyer/wasm_component_layer/pull/26). 

We chose the `wasmi_runtime` for native, and `js_wasm_runtime_layer` for the browser.
