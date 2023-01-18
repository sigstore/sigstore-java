# Setup test data

```shell
cp ../test-template/2.root.json . 
cp ../test-template/timestamp.json .
cp ../test-template/snapshot.json .
cp ../test-template/targets.json .
# modify the file so the hash doesn't match
sed -i 's/2023/2024/g' targets.json
```
