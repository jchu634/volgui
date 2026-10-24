fn main() {
    // GPUI's debug render paths need more than the MSVC default 1 MiB main-thread stack.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg-bin=volgui=/STACK:16777216");
    }
}
