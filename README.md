### How to Rust bindings for libFuzzer

_You can use the Rust fuzz ecosystem, which provides a convenient way to integrate fuzz testing into your Rust projects_

Here's a step-by-step guide on how to create Rust bindings for libFuzzer:

#### What is `libfuzzer`?
_libFuzzer is a highly efficient coverage-guided fuzz testing tool that is part of the LLVM (Low-Level Virtual Machine) project. Fuzz testing, or fuzzing, is a software testing technique in which a program is subjected to a large volume of random, invalid, or unexpected input data to discover vulnerabilities, crashes, or other issues._


#### Download `libfuzzer` C++ source code :

https://github.com/llvm/llvm-project/tree/main/compiler-rt/lib/fuzzer

#### Rust version
```bash
# rustc -vV
rustc 1.75.0-nightly (75b064d26 2023-11-01)
binary: rustc
commit-hash: 75b064d26970ca8e7a487072f51835ebb057d575
commit-date: 2023-11-01
host: x86_64-unknown-linux-gnu
release: 1.75.0-nightly
LLVM version: 17.0.4
```

#### Building for libfuzzer c++ code in the `build.rs`
```rust
    if let Ok(custom) = ::std::env::var("CUSTOM_LIBFUZZER_PATH") {

        let custom_lib_path = ::std::path::PathBuf::from(&custom);
        let custom_lib_dir = custom_lib_path.parent().unwrap().to_string_lossy();

        let custom_lib_name = custom_lib_path.file_stem().unwrap().to_string_lossy();
        let custom_lib_name = custom_lib_name.trim_start_matches("lib");
        println!("cargo:rustc-link-search=native={}", custom_lib_dir);
        println!("cargo:rustc-link-lib=static={}", custom_lib_name);
        println!("cargo:rustc-link-lib=stdc++");
    } else {
        let mut build = cc::Build::new();
        let sources = ::std::fs::read_dir("libfuzzer")
            .expect("listable source directory")
            .map(|de| de.expect("file in directory").path())
            .filter(|p| p.extension().map(|ext| ext == "cpp") == Some(true))
            .collect::<Vec<_>>();
        for source in sources.iter() {
            build.file(source.to_str().unwrap());
        }
        build.flag("-std=c++11");
        build.flag("-fno-omit-frame-pointer");
        build.flag("-w");
        build.cpp(true);
        build.compile("libfuzzer.a");
```

#### Add wrapper function `LLVMFuzzerTestOneInput` This wrapper function is designed to call a Rust function `rust_fuzzer_test_input` with input data obtained from the fuzzer.

```rust
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
```

#### Now starting fuzzing your libs with libfuzzer in rust.
```
$ cargo new --bin example
$ cd example
```
#### Then add a dependency on the fuzzer

```toml
[dependencies]
myfuzzer = { path = ".." }
your_crate_libs = "*"
```

#### And change code in your case ex: `src/main.rs` to fuzz my code:

```rust
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

```

#### Finally, run the following commands:

```bash
$ [03:18] raminfp@zenbook:example # cargo rustc -- \
    -C passes='sancov-module' \
    -C llvm-args='-sanitizer-coverage-level=3' \
    -C llvm-args='-sanitizer-coverage-inline-8bit-counters' \
    -Z sanitizer=address
$ ./target/debug/example
```
#### Output:

```bash 
[03:55] raminfp@zenbook:example # ./target/debug/example
INFO: Seed: 1157038402
INFO: Loaded 1 modules   (239 inline 8-bit counters): 239 [0x5556c7f79a80, 0x5556c7f79b6f), 
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED ft: 15 corp: 1/1b exec/s: 0 rss: 36Mb
#5	NEW    ft: 17 corp: 2/66b exec/s: 0 rss: 36Mb L: 65/65 MS: 3 CopyPart-CopyPart-InsertRepeatedBytes-
#58	REDUCE ft: 17 corp: 2/44b exec/s: 0 rss: 36Mb L: 43/43 MS: 3 InsertByte-InsertRepeatedBytes-EraseBytes-
#72	REDUCE ft: 17 corp: 2/25b exec/s: 0 rss: 36Mb L: 24/24 MS: 4 InsertByte-InsertByte-ChangeByte-EraseBytes-
#78	REDUCE ft: 17 corp: 2/24b exec/s: 0 rss: 36Mb L: 23/23 MS: 1 EraseBytes-
#80	REDUCE ft: 17 corp: 2/15b exec/s: 0 rss: 36Mb L: 14/14 MS: 2 CopyPart-EraseBytes-
#81	REDUCE ft: 17 corp: 2/14b exec/s: 0 rss: 36Mb L: 13/13 MS: 1 EraseBytes-
#133	REDUCE ft: 17 corp: 2/11b exec/s: 0 rss: 36Mb L: 10/10 MS: 2 ChangeBit-EraseBytes-
#171	REDUCE ft: 17 corp: 2/8b exec/s: 0 rss: 36Mb L: 7/7 MS: 3 ChangeBinInt-ChangeBit-EraseBytes-
#182	REDUCE ft: 17 corp: 2/6b exec/s: 0 rss: 36Mb L: 5/5 MS: 1 EraseBytes-
#184	REDUCE ft: 17 corp: 2/5b exec/s: 0 rss: 36Mb L: 4/4 MS: 2 InsertByte-EraseBytes-
#196	REDUCE ft: 17 corp: 2/3b exec/s: 0 rss: 36Mb L: 2/2 MS: 2 ChangeByte-EraseBytes-
thread '<unnamed>' panicked at src/main.rs:9:9:
Oops!
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
==44905== ERROR: libFuzzer: deadly signal
    #0 0x5556c7e6eaf1 in __sanitizer_print_stack_trace /rustc/llvm/src/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:87:3
    #1 0x5556c7eac540 in fuzzer::Fuzzer::CrashCallback() /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerLoop.cpp:233:38
    #2 0x5556c7eac3c6 in fuzzer::Fuzzer::StaticCrashSignalCallback() /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerLoop.cpp:206:19
    #3 0x5556c7edb561 in fuzzer::CrashHandler(int, siginfo_t*, void*) /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerUtilPosix.cpp:36:36
    #4 0x7efed284251f  (/lib/x86_64-linux-gnu/libc.so.6+0x4251f) (BuildId: a43bfc8428df6623cd498c9c0caeb91aec9be4f9)
    #5 0x7efed28969fb in __pthread_kill_implementation nptl/./nptl/pthread_kill.c:43:17
    #6 0x7efed28969fb in __pthread_kill_internal nptl/./nptl/pthread_kill.c:78:10
    #7 0x7efed28969fb in pthread_kill nptl/./nptl/pthread_kill.c:89:10
    #8 0x7efed2842475 in gsignal signal/../sysdeps/posix/raise.c:26:13
    #9 0x7efed28287f2 in abort stdlib/./stdlib/abort.c:79:7
    #10 0x5556c7ef8226 in std::sys::unix::abort_internal::haadb6d01b1ce5dcc /rustc/75b064d26970ca8e7a487072f51835ebb057d575/library/std/src/sys/unix/mod.rs:376:14
    #11 0x5556c7ddf7a6 in std::process::abort::hb7281d0b80ebbd50 /rustc/75b064d26970ca8e7a487072f51835ebb057d575/library/std/src/process.rs:2279:5
    #12 0x5556c7e945c5 in myfuzzer::test_input_wrap::_$u7b$$u7b$closure$u7d$$u7d$::h2f53ba4c17f7bd40 /home/raminfp/Projects/Develop/libfuzzer-rs/src/lib.rs:19:22
    #13 0x5556c7e94495 in core::option::Option$LT$T$GT$::map::h90a0dc092a0a2b55 /rustc/75b064d26970ca8e7a487072f51835ebb057d575/library/core/src/option.rs:1066:29
    #14 0x5556c7e94419 in LLVMFuzzerTestOneInput /home/raminfp/Projects/Develop/libfuzzer-rs/src/lib.rs:16:5
    #15 0x5556c7eadc73 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerLoop.cpp:515:15
    #16 0x5556c7ead6d1 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool*) /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerLoop.cpp:440:18
    #17 0x5556c7eae727 in fuzzer::Fuzzer::MutateAndTestOne() /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerLoop.cpp:648:25
    #18 0x5556c7eaf3ae in fuzzer::Fuzzer::Loop(std::vector<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, fuzzer::fuzzer_allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > const&) /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerLoop.cpp:775:21
    #19 0x5556c7e9b3ac in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerDriver.cpp:754:10
    #20 0x5556c7e94962 in main /home/raminfp/Projects/Develop/libfuzzer-rs/libfuzzer/FuzzerMain.cpp:20:30
    #21 0x7efed2829d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #22 0x7efed2829e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #23 0x5556c7de07f4 in _start (/home/raminfp/Projects/Develop/libfuzzer-rs/example/target/debug/example+0x127f4) (BuildId: 12917cdb5ef03b01c21eb307af3c31bd5867b94e)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 1 ChangeByte-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
0x41,
A
artifact_prefix='./'; Test unit written to ./crash-6dcd4ce23d88e2ee9568ba546c007c63d9131c1b
Base64: QQ==


```
#### Crash file: 
```bash

[03:20] raminfp@zenbook:example # exa
Cargo.lock  Cargo.toml  crash-6dcd4ce23d88e2ee9568ba546c007c63d9131c1b  src  target


[03:20] raminfp@zenbook:example # hexdump crash-6dcd4ce23d88e2ee9568ba546c007c63d9131c1b
0000000 0041                                   
0000001
```

Thanks,