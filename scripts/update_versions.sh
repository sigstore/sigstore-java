#!/bin/bash

# this script is simple and should work for most usecases, but it may break if we do weird things
set -Eeo pipefail

calculated_release_version=$(grep "^version=" gradle.properties | cut -d'=' -f2)
read -r -p "Enter released version [${calculated_release_version}]: " vin
release_version=${vin:-${calculated_release_version}}

calculated_previous_version=$(grep "sigstore-gradle-sign-plugin" build-logic/publishing/build.gradle.kts | cut -d':' -f3 | cut -d'"' -f1)
read -r -p "Enter previous version [${calculated_previous_version}]: " pvin
previous_version=${pvin:-${calculated_previous_version}}

calculated_next_version=$(echo "$release_version" | awk -F. -v OFS=. '{$2 += 1 ; print}')
read -r -p "Enter next version [${calculated_next_version}]: " nvin
next_version=${nvin:-${calculated_next_version}}

echo ""
echo "previous: $previous_version"
echo "latest  : $release_version"
echo "next    : $next_version"
read -r -p "Run update? [y/N]: " yn
go=${yn:-"n"}
if [ "${go,,}" != "y" ]; then
  echo "aborting"
  exit
fi

# sed below is probably accepting .'s in versions as regex any chars, but this works for our purposes

# updates to new release version
sed -i "s/\(sigstore-gradle-sign-plugin:\)$previous_version/\1$release_version/" build-logic/publishing/build.gradle.kts
sed -i "s/\(<version>\)$previous_version/\1$release_version/" sigstore-maven-plugin/README.md
sed -i "s/\(dev.sigstore.sign\") version \"\)$previous_version/\1$release_version/" sigstore-gradle/README.md
sed -i "s/\(sigstore.version.*\)$previous_version/\1$release_version/" examples/hello-world/build.gradle.kts
sed -i "s/\(<sigstore.version>\)$previous_version/\1$release_version/" examples/hello-world/pom.xml

# update to latest dev version
sed -i "s/\(sigstoreJavaVersion.convention(\"\)$release_version/\1$next_version/" sigstore-gradle/sigstore-gradle-sign-base-plugin/src/main/kotlin/dev/sigstore/sign/SigstoreSignExtension.kt
sed -i "s/version=$release_version/version=$next_version/" gradle.properties

