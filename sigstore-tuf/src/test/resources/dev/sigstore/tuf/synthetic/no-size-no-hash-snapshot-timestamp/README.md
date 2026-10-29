
```shell
cp ../test-template/2.root.json .
cp -R ../root-signing-workspace tmp
cd tmp
# remove hashes and length from snapshots and timestamp
jq -rc '.signed.meta."targets.json" |= del(.length, .hashes)' repository/snapshot.json | sponge repository/snapshot.json
jq -rc '.signed.meta."snapshot.json" |= del(.length, .hashes)' repository/timestamp.json | sponge repository/timestamp.json
# get valid sigs on the new snapshot metadata.
tuf payload snapshot.json > payload.snapshot.json
tuf sign-payload --role=snapshot payload.snapshot.json > snapshot.sigs
tuf add-signatures --signatures snapshot.sigs snapshot.json
cp staged/snapshot.json ../3.snapshot.json
# get valid sigs on the new timestamps metadata.
tuf payload timestamp.json > payload.timestamp.json
tuf sign-payload --role=timestamp payload.timestamp.json > timestamp.sigs
tuf add-signatures --signatures timestamp.sigs timestamp.json
cp staged/timestamp.json ../timestamp.json
cd ..
rm -rf tmp
```
