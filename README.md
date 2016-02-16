
telos - an ultimate object or aim. In this case to bring the sanity of
libtls into the Rust world. These bindings require libressl 2.3 (i.e. libtls9)
Have a look at the latest [docs](https://equalsraf.github.io/telos-docs/master/telos/).

## Building

Build using cargo, you will need the runtime libraries (libcrypto, libssl, libtls)

    $ cd telos
    $ cargo build

If you are linking against a library in a non standard location you need to override the linker library search paths before building, e.g.

    $ export LIBTLS_LIBRARY_PATH=/opt/libressl/lib
    $ cargo build

Likewise for the tls.h header

    $ export LIBTLS_INCLUDE_PATH=/opt/libressl/include

To force static linking

    $ export LIBTLS_LINKAGE=static

## Status

[![Travis-CI](https://travis-ci.org/equalsraf/telos.svg?branch=master)](https://travis-ci.org/equalsraf/telos)
[![Appveyor](https://ci.appveyor.com/api/projects/status/2vsds0x871hnws17?svg=true)](https://ci.appveyor.com/project/equalsraf/telos/branch/master)
[![Coverage Status](https://coveralls.io/repos/equalsraf/telos/badge.svg?branch=master&service=github)](https://coveralls.io/github/equalsraf/telos?branch=master)
