extern crate gcc;

use std::env;

fn main() {
    // build a minimal bit of C that checks the version/values from tls.h
    let mut gcc_cfg = gcc::Config::new();
    gcc_cfg.file("src/libressl_api_check.c");
    if let Ok(e_incpath) = env::var("LIBTLS_INCLUDE_PATH") {
        for path in env::split_paths(&e_incpath) {
            gcc_cfg.include(&path);
        }
    }
    gcc_cfg.compile("lib_api_check.a");

    // LIBTLS_LINKAGE (dylib, static, framework) is used to specify how
    // to link against libtls (see rustc-link-lib) - default is dylib
    let mode = env::var("LIBTLS_LINKAGE").unwrap_or("dylib".to_owned());

    // If available use the paths in LIBTLS_LIBRARY_PATH to search for libraries. 
    if let Ok(e_libpath) = env::var("LIBTLS_LIBRARY_PATH") {
        for path in env::split_paths(&e_libpath) {
            println!("cargo:rustc-link-search=native={}", &path.to_string_lossy());
        }
    }

    if let Ok(e_libs) = env::var("LIBTLS_LIBS") {
        // Link against the libraries in LIBTLS_LIBS, multiple
        // libraries can specified, separated by semicolon(;)
        for lib in e_libs.split(";") {
            println!("cargo:rustc-link-lib={}={}", mode, lib);
        }
    } else {
        // By default link against libtls. In static
        // builds link against libcrypto and libssl
        if mode == "static" {
            for lib in &["crypto", "ssl", "tls"] {
                println!("cargo:rustc-link-lib={}={}", mode, lib);
            }
        } else {
            println!("cargo:rustc-link-lib={}=tls", mode );
        }
    }
}
