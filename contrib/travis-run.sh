#!/bin/bash
set -e

export LIBRESSL_PATH=${PWD}/deps/libressl/lib

pushd tls
export LIBRESSL_LINKAGE=static
cargo build --verbose
cargo test --verbose
popd
