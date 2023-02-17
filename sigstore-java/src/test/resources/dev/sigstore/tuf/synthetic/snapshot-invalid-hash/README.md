# Setup test data

```shell
cp ../test-template/2.root.json . 
cp ../test-template/3.snapshot.json .
cp ../test-template/timestamp.json .
# modify the snapshot.json so the hash doesn't match
sed -i 's/2023/2025/g' 3.snapshot.json
```
