// SPDX-License-Identifier: FSL-1.1
use crate::{api, error::ApiError, Context, Error};
use tracing::info;
use wasmtime::{AsContextMut, Caller, Engine, FuncType, Linker, Val, ValType::*};

pub(crate) fn add_to_linker(
    engine: &Engine,
    linker: &mut Linker<Context<'_>>,
) -> Result<(), Error> {
    linker
        .func_new(
            "wacc",
            "_check_signature",
            FuncType::new(engine, [I32, I32, I32, I32], [I32]),
            check_signature,
        )
        .map_err(|e| ApiError::RegisterApiFailed(e.to_string()))?;
    Ok(())
}

pub(crate) fn check_signature(
    mut caller: Caller<'_, Context<'_>>,
    params: &[Val],
    results: &mut [Val],
) -> Result<(), wasmtime::Error> {
    // check preconditions
    if params.len() != 4 {
        let mut ctx = caller.as_context_mut();
        let context = ctx.data_mut();
        results[0] = context.fail("check_signature requires two string parameters");
        return Ok(());
    }

    // get the index and length of the pubkey and message key-path strings
    let (k, m) = params.split_at(2);
    info!("check_signature: {k:?}, {m:?}");

    // get the key-path string for the public key
    let key = match api::get_string(&mut caller, k) {
        Ok(kp) => kp,
        Err(e) => {
            let mut ctx = caller.as_context_mut();
            let context = ctx.data_mut();
            results[0] = context.fail(&e.to_string());
            return Ok(());
        }
    };

    // get the key-path string for the message
    let msg = match api::get_string(&mut caller, m) {
        Ok(msg) => msg,
        Err(e) => {
            let mut ctx = caller.as_context_mut();
            let context = ctx.data_mut();
            results[0] = context.fail(&e.to_string());
            return Ok(());
        }
    };

    // check the digital signature over the message
    let mut ctx = caller.as_context_mut();
    let context = ctx.data_mut();
    results[0] = context.check_signature(&key, &msg);
    info!(
        "check_signature(\"{key}\", \"{msg}\") -> {}",
        api::bool_result_display(&results[0])
    );

    Ok(())
}
