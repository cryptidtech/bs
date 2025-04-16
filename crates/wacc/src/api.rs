// SPDX-License-Identifier: FSL-1.1
pub(crate) mod branch;
pub(crate) mod check_eq;
pub(crate) mod check_preimage;
pub(crate) mod check_signature;
pub(crate) mod log;
pub(crate) mod push;

use crate::{error::ApiError, Context, Error};
use wasmtime::{AsContextMut, Caller, Engine, Extern, Linker, Val};

pub const WASM_TRUE: Val = Val::I32(1);
pub const WASM_FALSE: Val = Val::I32(0);

pub(crate) fn bool_result_display(ret: &Val) -> String {
    match ret {
        Val::I32(i) if *i == 0 => "false".to_string(),
        Val::I32(i) if *i == 1 => "true".to_string(),
        _ => "invalid return value".to_string(),
    }
}

/// Add the API functions to the given Linker
pub(crate) fn add_to_linker(
    engine: &Engine,
    linker: &mut Linker<Context<'_>>,
) -> Result<(), Error> {
    branch::add_to_linker(engine, linker)?;
    check_eq::add_to_linker(engine, linker)?;
    check_preimage::add_to_linker(engine, linker)?;
    check_signature::add_to_linker(engine, linker)?;
    log::add_to_linker(engine, linker)?;
    push::add_to_linker(engine, linker)?;
    Ok(())
}

/// This function takes an offset and length and pulls the associated bytes
/// from the linear memory and returns it as a string
pub(crate) fn get_string(
    caller: &mut Caller<'_, Context<'_>>,
    params: &[Val],
) -> Result<String, Error> {
    // get the mem
    let mem = match caller.get_export("memory") {
        Some(Extern::Memory(mem)) => mem,
        _ => return Err(ApiError::MissingExport("memory".to_string()).into()),
    };

    // make sure we have enough params
    if params.len() < 2 {
        return Err(ApiError::IncorrectNumberOfParams(2, params.len()).into());
    }

    // get the memory index
    let ptr = match params[0].i32() {
        Some(ptr) => ptr as u32 as usize,
        _ => return Err(ApiError::InvalidParam(0).into()),
    };

    // get the length
    let len = match params[1].i32() {
        Some(len) => len as u32 as usize,
        _ => return Err(ApiError::InvalidParam(1).into()),
    };

    // decode the string from the memory
    let s = {
        let mut buf = vec![0; len];
        buf.resize(len, 0u8);
        mem.read(&caller, ptr, buf.as_mut_slice())
            .map_err(|_| ApiError::MemoryDecodeError)?;
        String::from_utf8(buf)?
    };

    Ok(s)
}

/// This function takes
pub(crate) fn put_string(
    caller: &mut Caller<'_, Context<'_>>,
    s: &str,
    results: &mut [Val],
) -> Result<(), Error> {
    // make sure we have enough params
    if results.len() < 2 {
        return Err(ApiError::IncorrectNumberOfResults(2, results.len()).into());
    }

    // get the mem
    let mem = match caller.get_export("memory") {
        Some(Extern::Memory(mem)) => mem,
        _ => return Err(ApiError::MissingExport("memory".to_string()).into()),
    };

    // get the size
    let size = mem.data_size(&caller);

    let write_idx = {
        // get the context
        let mut ctx = caller.as_context_mut();
        let context = ctx.data_mut();

        // increment the write idx
        context.write_idx += s.len();

        // calculate the linear memory write index
        size - context.write_idx - 1
    };

    // put the offest and length on the stack
    results[0] = Val::I32(write_idx as i32);
    results[1] = Val::I32(s.len() as i32);

    // write the string into linear memory
    mem.write(caller, write_idx, s.as_bytes())
        .map_err(|e| ApiError::MemoryAccess(e.to_string()).into())
}
