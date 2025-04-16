#[link(wasm_import_module = "wacc")]
extern "C" {
    fn _check_signature(ptr: *const u8, len: usize) -> i32;
    fn _check_preimage(ptr: *const u8, len: usize) -> i32;
}

fn check_signature(key: &str) -> bool {
    unsafe { _check_signature(key.as_ptr(), key.len()) != 0 }
}

fn check_preimage(key: &str) -> bool {
    unsafe { _check_preimage(key.as_ptr(), key.len()) != 0 }
}

#[no_mangle]
pub fn move_zig() -> bool {
    check_signature("/tpubkey") || check_signature("/pubkey") || check_preimage("/hash")
}
