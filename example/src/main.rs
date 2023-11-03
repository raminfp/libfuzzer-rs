#![no_main]
extern crate myfuzzer;

#[export_name="rust_fuzzer_test_input"]
pub fn fuzz(data: &[u8]) {
    // your fuzz code here
    // println!("{:?}", data);
    if data == b"A" {
        panic!("Oops!");
    }
}
