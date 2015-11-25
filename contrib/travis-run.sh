#!/bin/bash
set -ev

export LIBRESSL_PATH=${PWD}/deps/lib
export LIBRESSL_INCLUDE=${PWD}/deps/include

export LIBRESSL_LINKAGE=static
cargo test --verbose --manifest-path tls/Cargo.toml

