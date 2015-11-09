#!/bin/bash
set -e

# Travis
#
# install libressl into deps/libressl, patch it first to point libtls
# to the correct ca-file.
#

LIBRESSL=libressl-2.3.1
DEPS=${PWD}/deps

if [ -d "$DEPS/libressl" ]; then
	echo "Skipping instalation of ${LIBRESSL}"
else
	wget http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/${LIBRESSL}.tar.gz
	echo "37c765c6a452e1dd6c5ed368d618c05e5875715e *${LIBRESSL}.tar.gz" | sha1sum -c -
	tar axf ${LIBRESSL}.tar.gz
	pushd ${LIBRESSL}
	patch -p0 < ../contrib/libressl-ca-file.patch
	./configure --prefix=${DEPS}/libressl
	make CFLAGS='-fPIC -D_PATH_SSL_CA_FILE=\"/etc/ssl/certs/ca-certificates.crt\"'
	make install
	popd
fi
