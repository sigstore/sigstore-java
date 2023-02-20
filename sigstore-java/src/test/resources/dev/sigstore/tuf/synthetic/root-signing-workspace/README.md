
# TUF repo creation steps

You'll need the TUF cli to run these commands. 
```shell
go install github.com/theupdateframework/go-tuf/cmd/tuf@latest
```

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
tuf snapshot --expires=60
tuf timestamp --expires=30
tuf commit 
cp repository/1.root.json ../trusted-root.json  # this is our trusted root for synthetic
cp repository/timestamp.json repository/1.timestamp.json # backup an old timestamp.json for some testcases
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
```

NOTE:  It can help with readability to reformat the json files. snapshot.json and targets.json should not be reformatted
due to hash validation checks. You can always revert a reformat to one of those files by removing all whitespace.
