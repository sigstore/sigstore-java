# Setup test data

```shell
cp ../test-template/2.root.json . 
cp ../test-template/snapshot.json .
# modify the snapshot.json so the hash doesn't match
sed -i 's/2022/2023/g' snapshot.json
# setup signing workspace to modify the timestamp.json
cp -R ../root-signing-workspace ./tmp
cd tmp
# don't resign snapshot as we won't get that far.
# update the snapshot size in timestamp so it's valid.
jq -r --argjson length $(wc -c repository/snapshot.json | awk '{ print $1 }') '.signed.meta."snapshot.json".length |= $length' repository/timestamp.json | sponge repository/timestamp.json
# re-sign the timestamp.json now that we've altered it
tuf payload timestamp.json > payload.timestamp.json  
tuf sign-payload --role=timestamp payload.timestamp.json > timestamp.sigs
tuf add-signatures --signatures timestamp.sigs timestamp.json 
cp staged/timestamp.json ../.
```
