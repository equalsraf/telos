
Bindings for libressl's libtls. These bindings require libressl 2.3 (i.e. libtls9)

## Building

Build using cargo, you need the runtime libraries (libcrypto, libssl, libtls)

    $ cd tls
    $ cargo build

If you are linking against a library in a non standard location you need to override the linker library search paths before building, e.g.

    $ export LIBTLS_LIBRARY_PATH=/opt/libressl/lib
    $ cargo build

Likewise for the tls.h header

    $ export LIBTLS_INCLUDE_PATH=/tmp/libressl/include

To force static linking

    $ export LIBTLS_LINKAGE=static

[![Travis-CI](https://travis-ci.org/equalsraf/rust-tls.svg?branch=master)](https://travis-ci.org/equalsraf/rust-tls)
[![Coverage Status](https://coveralls.io/repos/equalsraf/rust-tls/badge.svg?branch=master&service=github)](https://coveralls.io/github/equalsraf/rust-tls?branch=master)
