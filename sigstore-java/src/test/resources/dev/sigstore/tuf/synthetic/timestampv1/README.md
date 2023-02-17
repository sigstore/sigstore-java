# Setup test data

```shell
cp -R ../root-signing-workspace tmp
cd tmp
# downgrade the snapshot version to trigger SnapshotTargetVersionException
jq -r '.signed.version |= 1' repository/timestamp.json | sponge repository/timestamp.json
# update the snapshot hash and length in timestamp so it matches snapshot v1.
jq -r --argjson length $(wc -c repository/1.snapshot.json | awk '{ print $1 }') '.signed.meta."snapshot.json".length |= $length' repository/timestamp.json | sponge repository/timestamp.json
jq -r --arg sha "$(sha512sum repository/1.snapshot.json | awk '{ print $1 }')" '.signed.meta."snapshot.json".hashes.sha512 |= $sha' repository/timestamp.json | sponge repository/timestamp.json
jq -r '.signed.meta."snapshot.json".version |= 1' repository/timestamp.json | sponge repository/timestamp.json
# re-sign the timestamp.json now that we've altered it
tuf payload timestamp.json > payload.timestamp.json  
tuf sign-payload --role=timestamp payload.timestamp.json > timestamp.sigs
tuf add-signatures --signatures timestamp.sigs timestamp.json 
cp staged/timestamp.json ../1.timestamp.json
cd ..
rm -rf tmp
```
