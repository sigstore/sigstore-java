
# TUF repo creation steps

```shell
mkdir root-signing-workspace
cd root-signing-workspace
tuf init --consistent-snapshot=false
tuf gen-key --expires=90 --scheme="ecdsa-sha2-nistp256" root
tuf gen-key --expires=120 --scheme="ecdsa-sha2-nistp256" root
tuf gen-key --expires=150 --scheme="ecdsa-sha2-nistp256" root
tuf gen-key --expires=90 --scheme="ecdsa-sha2-nistp256" targets
tuf gen-key --expires=90 --scheme="ecdsa-sha2-nistp256" snapshot
tuf gen-key --expires=90 --scheme="ecdsa-sha2-nistp256" timestamp
echo "test file" > staged/targets/test.txt
tuf add test.txt
tuf snapshot
tuf timestamp
tuf commit 
cp repository/1.root.json ../trusted-root.json  # this is our trusted root for synthetic
echo "test target v2" > staged/targets/test.txt.v2
tuf add test.txt.v2
tuf snapshot
tuf timestamp
tuf commit # creates new timestamp and snapshot versions
# Do it all again to get another version for timestamp and snapshot.
echo "another test file" > staged/targets/test2.txt
tuf add test2.txt
tuf snapshot
tuf timestamp
tuf commit
# Now we want a new root version
tuf set-threshold root 2
tuf commit
cp -R repository ../test-template # Now we have a decent synthetic test repo to use for most tests.
echo "another target" > staged/targets/test2.txt
tuf add test2.txt
tuf snapshot
tuf timestamp
jq -r '.signed.targets."sample.file".length |= 29' staged/targets.json # modify the file so the hash doesn't match
tuf payload snapshot.json > payload.snapshot.json  
tuf sign-payload --role=snapshot payload.snapshot.json > snapshot.sigs
tuf add-signatures --signatures snapshot.sigs snapshot.json  # we've added a good sig despite the bad hash 
```
