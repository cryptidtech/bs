// SPDX-License-Identifier: FSL-1.1

/// virtual machine builder
pub mod builder;

/// wasm code compiler
pub mod compiler;

/// virtual machine execution context
pub mod context;

/// virtual machine instance
pub mod instance;

/// value wrapper used in the virtual machine
pub mod value;

pub use builder::Builder;
pub use compiler::Compiler;
pub use context::Context;
pub use instance::Instance;
pub use value::Value;
