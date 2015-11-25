extern crate gcc;

use std::env;

fn main() {
    // build a minimal bit of C that checks the version/values from tls.h
    let mut gcc_cfg = gcc::Config::new();
    gcc_cfg.file("src/libressl_api_check.c");
    if let Ok(e_incpath) = env::var("LIBRESSL_INCLUDE") {
        gcc_cfg.include(&e_incpath);
    }
    gcc_cfg.compile("lib_api_check.a");

    // LIBRESSL_LINKAGE (dylib, static, framework) is used to specify how
    // to link against libtls (see rustc-link-lib) - default is dylib
    let mode = env::var("LIBRESSL_LINKAGE").unwrap_or("dylib".to_owned());

    // If available use the paths in LIBRESSL_PATH to search for libraries. 
    if let Ok(e_libpath) = env::var("LIBRESSL_PATH") {
        for path in env::split_paths(&e_libpath) {
            println!("cargo:rustc-link-search=native={}", &path.to_string_lossy());
        }
    }

    // Link against crypto, ssl and tls. 
    for lib in &["crypto", "ssl", "tls"] {
        println!("cargo:rustc-link-lib={}={}", mode, lib);
    }
}
