#!/bin/bash
set -ev

# Run tests by hand with kcov
KCOV=${PWD}/deps/bin/kcov
KCOV_ARGS="--coveralls-id=${TRAVIS_JOB_ID} --exclude-pattern=/tests/,/crypto/,/ssl/ ../kcov-out"

# Somes tests need to be in the crate folder
pushd tls
for f in target/debug/*
do
	if [ -f "$f" ] && [ -x "$f" ]; then
		${KCOV} ${KCOV_ARGS} $f
	fi
done

popd
