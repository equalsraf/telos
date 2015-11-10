
Bindings for libressl's libtls.

## Building

Build using cargo, you need the runtime libraries (libcrypto, libssl, libtls)

    $ cd tls
    $ cargo build

If you are linking against a library in a non standard location you need to override the linker library search paths before building, e.g.

    $ export LIBRESSL_PATH=/opt/libressl/lib
    $ cargo build

To force static linking

    $ export LIBRESSL_LINKAGE=static

[![Travis-CI](https://travis-ci.org/equalsraf/rust-tls.svg?branch=master)](https://travis-ci.org/equalsraf/rust-tls)
[![Coverage Status](https://coveralls.io/repos/equalsraf/rust-tls/badge.svg?branch=master&service=github)](https://coveralls.io/github/equalsraf/rust-tls?branch=master)
