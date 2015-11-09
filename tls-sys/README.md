FFI declarations for libtls.

If you are linking against a library in a non standard location you need to override the linker library search paths before building, e.g.

    $ export LIBRESSL_PATH=/tmp/libressl/build/lib;
    $ cargo build

To force static linking

    $ export LIBRESSL_LINKAGE=static

If you just want to check if the linkage succeeded there is a minimal test available (that just calls `tls_init()`). You may need to set `LD_LIBRARY_PATH` before running it.

    $ cargo test

