#[link(wasm_import_module = "wacc")]
extern "C" {
    fn _check_version(expected: i64) -> i32;
    fn _check_signature(ptr: *const u8, len: usize) -> i32;
}

fn check_version(expected: usize) -> bool {
    unsafe { _check_version(expected as i64) != 0 }
}

fn check_signature(key: &str) -> bool {
    unsafe { _check_signature(key.as_ptr(), key.len()) != 0 }
}

#[no_mangle]
pub fn move_zig() -> bool {
    check_version(0) && check_signature("ephemeral")
}
