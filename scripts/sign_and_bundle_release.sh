#!/bin/bash
set -e

# ask github for the latest release
# todo: maybe change to take an input
echo "downloading latest release from github"
RELEASE_INFO=$(curl -s -H "Accept: application/vnd.github+json" https://api.github.com/repos/sigstore/sigstore-java/releases/latest)
RELEASE_VERSION="$(echo $RELEASE_INFO | jq -r '.tag_name')"
RELEASE_DIR="release_${RELEASE_VERSION}"

echo "release version is: ${RELEASE_VERSION}"

if [ -d $RELEASE_DIR ]; then
  echo "Directory '$RELEASE_DIR' already exists"
  exit 1
fi

# query the json for all the release assets
ASSET_URLS=$(echo $RELEASE_INFO | jq -r '.assets[].browser_download_url')

echo "downloading release artifacts"
for i in ${ASSET_URLS[@]}
do
  echo "$i"
  wget -q --directory-prefix $RELEASE_DIR "$i"
done
cd $RELEASE_DIR

# cosign sign all the files
echo "signing with cosign"
for file in *; do
  # skip intoto attestations, they are already signed
  if [ $file == *.intoto.jsonl ] ; then
    continue;
  fi
  COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes $file --output-signature=$file.sig --output-certificate=$file.pem --bundle $file.bundle
done

# then gpg sign all the files (including sigstore files)
# this command uses gpgs default password acceptance mechansim accept a passcode
echo "signing with gpg"
for file in *; do
  gpg --batch --detach-sign --armor -o $file.asc $file
done

# create a maven central compatible bundle jar
echo "creating maven bundle"
POM=$(ls *.pom)
BUNDLE_NAME=${POM%.pom}-bundle.jar
jar -cvf "${BUNDLE_NAME}" *

echo "Upload $(realpath $BUNDLE_NAME) to maven central (https://s01.oss.sonatype.org)"
