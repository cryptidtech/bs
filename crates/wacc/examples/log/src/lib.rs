#[link(wasm_import_module = "wacc")]
extern "C" {
    fn _log(ptr: *const u8, len: usize) -> bool;
}

fn log(s: &str) -> bool {
    unsafe { _log(s.as_ptr(), s.len()) }
}

#[no_mangle]
pub fn move_every_zig() -> bool {
    log("Hello World!")
}
