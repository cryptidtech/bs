// SPDX-License-Identifier: FSL-1.1
use crate::{
    api,
    error::ApiError,
    Context, Error,
};
use wasmtime::{AsContextMut, Caller, Engine, FuncType, Linker, Val, ValType::*};

pub(crate) fn add_to_linker<'a>(engine: &Engine, linker: &mut Linker<Context<'a>>) -> Result<(), Error>
{
    linker
        .func_new("wacc", "_pop", FuncType::new(engine, [], [I32]), pop)
        .map_err(|e| ApiError::RegisterApiFailed(e.to_string()))?;
    Ok(())
}

pub(crate) fn pop<'a, 'b, 'c>(
    mut caller: Caller<'a, Context<'b>>,
    params: &'c [Val],
    results: &mut [Val],
) -> Result<(), wasmtime::Error>
{
    // get the context
    let mut ctx = caller.as_context_mut();
    let context = ctx.data_mut();

    // call the function
    results[0] = context.pop()

    Ok(())
}
