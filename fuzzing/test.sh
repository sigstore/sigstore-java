#!/bin/bash -eu

# TODO AdamKorcz: Make the build script a gradle module

# build the fuzzing classes and extract dependencies into the build/fuzzRoot
BUILD_OUT="./build/fuzzRoot"

for fuzzer in $(find "$BUILD_OUT" -name '*Fuzzer.class' | xargs realpath --relative-to "$BUILD_OUT"); do
  echo $fuzzer
  fuzzer_basename=$(basename -s .class $fuzzer)
  echo $fuzzer_basename
  dir_name=$(dirname $fuzzer)
  fuzzer_package=${dir_name//\//\.}
  echo $fuzzer_package
  fuzzer_target="${fuzzer_package}.${fuzzer_basename}"
  echo $fuzzer_target
done
