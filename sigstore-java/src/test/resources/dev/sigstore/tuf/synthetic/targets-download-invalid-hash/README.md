# Setup test data

```shell
cp ../test-template/2.root.json .
cp ../test-template/timestamp.json .
cp ../test-template/snapshot.json .
cp ../test-template/targets.json .
mkdir targets
cp ../test-template/targets/test.txt targets/.
# Modify test.txt target so has is invalid
cat targets/test.txt | tr 'f' 'm' | sponge targets/test.txt
```
