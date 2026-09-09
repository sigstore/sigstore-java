# Setup test data

```shell
cp ../test-template/2.root.json . 
cp -R ../root-signing-workspace tmp
cd tmp
# update the version and remove the target so that we trigger SnapshotTargetMissingException
jq -r '.signed.version |= 4' repository/snapshot.json | sponge repository/snapshot.json
jq -r '.signed.meta |= {}' repository/snapshot.json | sponge repository/snapshot.json
# get valid sigs on the new snapshot metadata.
tuf payload snapshot.json > payload.snapshot.json  
tuf sign-payload --role=snapshot payload.snapshot.json > snapshot.sigs
tuf add-signatures --signatures snapshot.sigs snapshot.json 
cp staged/snapshot.json ../4.snapshot.json
 # update the snapshot hash in timestamp so it's valid.
jq -r --arg sha "$(sha512sum staged/snapshot.json | awk '{ print $1 }')" '.signed.meta."snapshot.json".hashes.sha512 |= $sha' repository/timestamp.json | sponge repository/timestamp.json
jq -r '.signed.meta."snapshot.json".version |= 4' repository/timestamp.json | sponge repository/timestamp.json
# re-sign the timestamp.json now that we've altered it
tuf payload timestamp.json > payload.timestamp.json  
tuf sign-payload --role=timestamp payload.timestamp.json > timestamp.sigs
tuf add-signatures --signatures timestamp.sigs timestamp.json 
cp staged/timestamp.json ../timestamp.json
cd ..
rm -rf tmp
```
