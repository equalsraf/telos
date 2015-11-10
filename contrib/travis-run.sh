#!/bin/bash
set -ev

export LIBRESSL_PATH=${PWD}/deps/libressl/lib

export LIBRESSL_LINKAGE=static
cargo test --verbose --manifest-path tls/Cargo.toml
