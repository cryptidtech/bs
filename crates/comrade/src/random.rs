//! Implements random for this wasm32-unknown-unknown target.
//!
//! Since we was wasm but ARE NOT int he browser, we need to use the
//! custom function to generate random bytes.
//!
//! However, since getrandom v0.2 and v0.3 are both present in dependencies,
//! and have different APIs, we need to implement both of them.
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::window;

/// Browser getrandom v0.3 requires RUSTFLAGS='--cfg getrandom_backend="wasm_js"'  
/// and this function.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    // Safety: This is safe because we are using the imported_random function
    // which is safe to use in this context.
    let slice = unsafe { std::slice::from_raw_parts_mut(dest, len) };

    // if wasm32, then use Crypto::getRandomValues(&mut buffer);
    // if not wasm32, just use getrandom::fill(&mut buffer);
    #[cfg(target_arch = "wasm32")]
    {
        bindgen_byte(slice).map_err(|_| getrandom::Error::UNSUPPORTED)?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::fill(slice)
    }
}

#[cfg(target_arch = "wasm32")]
fn bindgen_byte(buffer: &mut [u8]) -> Result<(), JsValue> {
    let window = window().ok_or_else(|| JsValue::from_str("window not available"))?;
    let crypto = window.crypto()?;
    crypto.get_random_values_with_u8_array(buffer)?;
    Ok(())
}
