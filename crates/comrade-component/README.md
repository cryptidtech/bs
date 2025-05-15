# Comrade Component

## Overview

This is an example of how the comrade reference implementation can be used to create a wasm component. To give the system maximum flexibility, any user wishing to use their own implementation can build their own component with the same interface and use that instead. 

## Building

To build the component, run the following command:

Prerequisites:

- [cargo-component](https://github.com/bytecodealliance/cargo-component) installed
- [just](https://just.systems/) installed (opional)

```bash
just build
```

This will create a `comrade_component.wasm` file in the `target/wasm32-unknown-unknown/release` directory. This file can be used as a component as a Sctrip runtime in your comrade application, if desired.

Next, use the `comrade::runtime::layer` (or build a wasmtime runtime module) to run the component. The `comrade::runtime::layer` will automatically load the component and make it available to the comrade application.

## Experimental Feature

*Note that this feature is experimental and not used, nor well supported at this time. It is meant as a demonstration for users who wish to pursue this path. If desired by the community, we can add more support for this in the future.
