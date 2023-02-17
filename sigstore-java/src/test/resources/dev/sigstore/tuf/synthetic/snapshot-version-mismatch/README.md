# Setup test data

```shell
cp ../test-template/2.root.json .
cp -R ../root-signing-workspace ./tmp
cd tmp
# modify the snapshot to have a version which doesn't match timestamp.
jq -r '.signed.version |= 2' repository/snapshot.json | sponge repository/snapshot.json
cp repository/snapshot.json repository/3.snapshot.json
# re-sign the snapshot.json so that it looks trusted
tuf payload snapshot.json > payload.snapshot.json  
tuf sign-payload --role=snapshot payload.snapshot.json > snapshot.sigs
tuf add-signatures --signatures snapshot.sigs snapshot.json 
cp staged/snapshot.json ../.
cp ../snapshot.json ../3.snapshot.json
# update the snapshot hash in timestamp so it's valid.
jq -r --argjson length $(wc -c staged/snapshot.json | awk '{ print $1 }') '.signed.meta."snapshot.json".length |= $length' repository/timestamp.json | sponge repository/timestamp.json
jq -r --arg sha "$(sha512sum staged/snapshot.json | awk '{ print $1 }')" '.signed.meta."snapshot.json".hashes.sha512 |= $sha' repository/timestamp.json | sponge repository/timestamp.json
# re-sign the timestamp.json now that we've altered it
tuf payload timestamp.json > payload.timestamp.json  
tuf sign-payload --role=timestamp payload.timestamp.json > timestamp.sigs
tuf add-signatures --signatures timestamp.sigs timestamp.json 
cp staged/timestamp.json ../.
cd ..
rm -rf tmp
```
