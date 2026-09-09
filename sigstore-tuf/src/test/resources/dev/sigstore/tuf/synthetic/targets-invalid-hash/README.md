# Setup test data

```shell
cp ../test-template/2.root.json . 
cp ../test-template/timestamp.json .
cp ../test-template/3.snapshot.json .
cp ../test-template/3.targets.json .
# modify the file so the hash doesn't match
sed -i 's/2023/2024/g' 3.targets.json
```
