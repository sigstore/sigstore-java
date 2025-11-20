#!/bin/bash

# change the targetted release version without adjust anything else in the build, typically you 
# only need this script if you're doing a bug fix or a release candidate (-rc)

# this script is simple and should work for most usecases, but it may break if we do weird things
set -Eeo pipefail

old_version=$(grep "^version=" gradle.properties | cut -d'=' -f2)
other_old_version=$(grep "sigstoreJavaVersion.convention" sigstore-gradle/sigstore-gradle-sign-base-plugin/src/main/kotlin/dev/sigstore/sign/SigstoreSignExtension.kt | cut -d'"' -f2)
if [[ "$old_version" != "$other_old_version" ]]; then
  echo "found version are not equal ($old_version != $other_old_version) ... aborting"
  exit
fi
read -r -p "Enter new version [${old_version}]: " vin
new_version=${vin:-${old_version}}

echo ""
echo "old  : $old_version"
echo "new  : $new_version"
read -r -p "Run update? [y/N]: " yn
go=${yn:-"n"}
if [ "${go,,}" != "y" ]; then
  echo "aborting"
  exit
fi

# update to latest dev version (change update_versions.sh if you change this section)
sed -i "s/\(sigstoreJavaVersion.convention(\"\)$old_version/\1$new_version/" sigstore-gradle/sigstore-gradle-sign-base-plugin/src/main/kotlin/dev/sigstore/sign/SigstoreSignExtension.kt
sed -i "s/version=$old_version/version=$new_version/" gradle.properties

