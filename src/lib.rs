use std::slice::from_raw_parts;

extern "C" {
    fn rust_fuzzer_test_input(data: *const u8, len: usize);
}

#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {

    let _ = unsafe { from_raw_parts(data, size) };

    unsafe {
        rust_fuzzer_test_input(data, size);
    }
    0
}