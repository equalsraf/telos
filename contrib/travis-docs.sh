#! /bin/bash
set -ev

# Change SOURCE/DEPLOY_REPO and upload a new key if
# you want to use this. see travis encrypt-file for
# encrypting the KEY_FILE
DEPLOY_REPO="git@github.com:equalsraf/rust-tls-docs.git"
SOURCE="equalsraf/rust-tls"

if [ -z $PUSH_DOCS ]; then
	echo "Skipping docs (disabled)"
	exit 0
fi

if [ "$TRAVIS_REPO_SLUG" != "$SOURCE"]; then
	echo "Skipping docs (clone)"
	exit 0
fi

if [ "$TRAVIS_PULL_REQUEST" == "true" ]; then
	echo "Skipping docs for (PR)"
	exit 0
fi

# Decrypt deploy key
KEY_FILE=contrib/travis-docs-deploy.key
openssl aes-256-cbc -K $encrypted_ba69868acafa_key -iv $encrypted_ba69868acafa_iv -in contrib/travis-docs-deploy.key.enc -out $KEY_FILE -d
chmod 600 $KEY_FILE
eval "$(ssh-agent -s)"
ssh-add $KEY_FILE

# Generate docs
cargo doc --manifest-path tls/Cargo.toml

# Push
git clone --branch gh-pages "${DEPLOY_REPO}"
pushd rust-tls-docs
if [ ! -d "$TRAVIS_BRANCH" ]; then
	mkdir $TRAVIS_BRANCH
fi
pushd $TRAVIS_BRANCH
rm -rf *

cp -R ../../tls/target/doc/* .

# kcov report
cp -R ../../kcov-out kcov

git config user.name "rust-tls CI"
git config user.email "rust-tls@travis"
git config push.default simple
git add -A .
git commit -q -m "Build docs/${TRAVIS_BRANCH} from ${TRAVIS_COMMIT}"
git push
popd
