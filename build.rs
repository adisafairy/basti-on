// Compiles the C++ parser and the cxx glue into the Rust crate.
//
// By default the C++ is built WITHOUT AddressSanitizer, so `cargo test` and the
// benchmark link cleanly. The fuzz sub-crate sets AIRLOCK_ASAN=1 to rebuild the
// C++ with -fsanitize=address so over-reads become hard crashes the fuzzer can
// catch.

fn main() {
    let asan = std::env::var("AIRLOCK_ASAN").is_ok();

    let mut build = cxx_build::bridge("src/lib.rs");
    build
        .file("cpp/src/dns_parser.cpp")
        .file("cpp/src/dns_parser_bridge.cc")
        .include("cpp/include")
        .std("c++17")
        .warnings(false);

    if asan {
        build.flag_if_supported("-fsanitize=address");
        build.flag_if_supported("-fno-omit-frame-pointer");
        build.flag_if_supported("-g");
    }

    build.compile("dns_parser");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cpp/src/dns_parser.cpp");
    println!("cargo:rerun-if-changed=cpp/src/dns_parser_bridge.cc");
    println!("cargo:rerun-if-changed=cpp/include/dns_parser.h");
    println!("cargo:rerun-if-changed=cpp/include/dns_parser_bridge.h");
    println!("cargo:rerun-if-env-changed=AIRLOCK_ASAN");
}
