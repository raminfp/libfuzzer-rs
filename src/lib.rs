use std::slice::from_raw_parts; // safe rust slice from a raw pointer
use std::panic::catch_unwind; // allowing the code to handle errors
use std::process::abort; // terminate the process if a panic is caught

extern "C" {
    #![allow(improper_ctypes)]
    fn rust_fuzzer_test_input(input: &[u8]);
}

#[export_name="LLVMFuzzerTestOneInput"] // This export name is important for linking with external tools like libFuzzer.
pub fn test_input_wrap(data: *const u8, size: usize) -> i32 {
    /*
        data: A raw pointer to the input data.
        size: The size of the input data.
    */
    catch_unwind(|| unsafe {
        let data_slice = from_raw_parts(data, size);
        rust_fuzzer_test_input(data_slice);
    }).err().map(|_| abort());
    0
}