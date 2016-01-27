#!/bin/bash
set -ev

export LIBTLS_LIBRARY_PATH=${PWD}/deps/lib
export LIBTLS_INCLUDE_PATH=${PWD}/deps/include
export LIBTLS_LINKAGE=static
export RUST_BACKTRACE=1
cargo test --verbose --manifest-path tls/Cargo.toml
