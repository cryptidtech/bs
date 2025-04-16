#[link(wasm_import_module = "wacc")]
extern "C" {
    fn _push(ptr: *const u8, len: usize) -> bool;
}

fn push(key: &str) -> bool {
    unsafe { _push(key.as_ptr(), key.len()) }
}

#[no_mangle]
pub fn for_great_justice() -> bool {
    // push "/entry/"
    push("/entry/");
    // push "/entry/proof"
    push("/entry/proof");

    true
}
