#!/bin/bash -eu

# TODO: this should be a gradle plugin

# build the fuzzing classes and extract dependencies into $OUT
./gradlew :fuzzing:copyToFuzzOut -x test -PfuzzOut="$OUT"
ALL_JARS=""
for jarfile in $(find $OUT -name *.jar)
do
  ALL_JARS="$ALL_JARS $(basename $jarfile)"
done

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

# Create all fuzzing targets
for fuzzer in $(find "$OUT" -name '*Fuzzer.class' | xargs realpath --relative-to "$OUT"); do
  fuzzer_basename=$(basename -s .class $fuzzer)
  if [[ "$fuzzer_basename" == "KeylessSigningFuzzer" ]]; then
    continue
  fi
  dir_name=$(dirname $fuzzer)
  fuzzer_package=${dir_name//\//\.}
  fuzzer_target="${fuzzer_package}.${fuzzer_basename}"

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
--target_class=$fuzzer_target \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
