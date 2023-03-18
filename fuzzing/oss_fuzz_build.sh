#!/bin/bash -eu

# TODO AdamKorcz: Make the build script a gradle module

./gradlew clean build -x test --refresh-dependencies

CURRENT_VERSION=$(./gradlew properties --no-daemon --console=plain -q | grep "^version:" | awk '{printf $2}')
cp sigstore-java/build/libs/sigstore-java-$CURRENT_VERSION.jar $OUT/sigstore-java.jar

# Search for dependency jars from gradle local repository,
# move them to the $OUT directory and add them to the ALL_JARS
# variable to allow jvm to use them as class path when compiling
# and executing the fuzzers which depends on them
ALL_JARS=sigstore-java.jar
for jarfile in $(find ~/.gradle/caches/modules-2/files-2.1/ \( -iname "*.jar" ! -iname "junit*" ! -iname "spotless*" ! -iname "ktlint*" ! -iname "gradle*" ! -iname "kotlin*" \))
do
  cp $jarfile $OUT/
  ALL_JARS="$ALL_JARS $(basename $jarfile)"
done

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC/sigstore-java/fuzzing -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  if [[ "$fuzzer_basename" == "KeylessSigningFuzzer" ]]; then
    continue
  fi
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/sigstore-java/fuzzing/$fuzzer_basename.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
