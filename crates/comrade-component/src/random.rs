//! Implements random for this wasm32-unknown-unknown target.
//!
//! Since we was wasm but ARE NOT int he browser, we need to use the
//! custom function to generate random bytes.
//!
//! However, since getrandom v0.2 and v0.3 are both present in dependencies,
//! and have different APIs, we need to implement both of them.
use super::bindings::comrade::api::utils::random_byte;

/// getrandom v0.2 requires the 'cusotm' flag and this custom function to use the import for random byte generation.
///
/// We do this is because "js" feature is incompatible with the component model
/// if you ever got the __wbindgen_placeholder__ error when trying to use the `js` feature
/// of getrandom,
pub fn imported_random(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    // iterate over the length of the destination buffer and fill it with random bytes
    (0..dest.len()).for_each(|i| {
        dest[i] = random_byte();
    });

    Ok(())
}

// for getrandom v0.2 custom function
getrandom::register_custom_getrandom!(imported_random);

/// getrandom v0.3 requires the 'custom' RUSTFLAG and this function below:
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    // Safety: This is safe because we are using the imported_random function
    // which is safe to use in this context.
    let slice = unsafe { std::slice::from_raw_parts_mut(dest, len) };
    imported_random(slice)
}
