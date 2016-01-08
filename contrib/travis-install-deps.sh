#!/bin/bash
set -ev

# Travis
#
# install libressl into deps/libressl, patch it first to point libtls
# to the correct ca-file.
#

LIBRESSL=libressl-2.3.1
DEPS=${PWD}/deps

if [ -x "$DEPS/bin/openssl" ]; then
	echo "Skipping instalation of ${LIBRESSL}"
else
	wget http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/${LIBRESSL}.tar.gz
	echo "37c765c6a452e1dd6c5ed368d618c05e5875715e *${LIBRESSL}.tar.gz" | sha1sum -c -
	tar axf ${LIBRESSL}.tar.gz
	pushd ${LIBRESSL}
	patch -p0 < ../contrib/libressl-ca-file.patch
	./configure --prefix=${DEPS}
	make CFLAGS='-g -fPIC -D_PATH_SSL_CA_FILE=\"/etc/ssl/certs/ca-certificates.crt\"'
	make install
	popd
fi

KCOV_VERSION=30
if [ -x "$DEPS/bin/kcov" ]; then
	echo "Skipping instalation of kcov"
else
	wget -O kcov.tar.gz https://github.com/SimonKagstrom/kcov/archive/v${KCOV_VERSION}.tar.gz
	echo "c2111b89acd114f7526123a5d41707c532fad02e *kcov.tar.gz" | sha1sum -c -
	tar axf kcov.tar.gz
	pushd kcov-${KCOV_VERSION}
	mkdir build
	pushd build
	cmake -DCMAKE_INSTALL_PREFIX=${DEPS} ..
	make install
	popd
	popd
fi

