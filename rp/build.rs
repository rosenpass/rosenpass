// build.rs
use std::env;

fn main() {
    //Increase stack size for Windows
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg=/stack:{}", 16 * 1024 * 1024);
    }
}