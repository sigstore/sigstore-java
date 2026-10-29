# Setup test data

```shell
cp ../test-template/2.root.json .
cp ../test-template/timestamp.json .
## remove sigs
jq -r '.signatures |= []' timestamp.json > timestamp.new
rm timestamp.json && mv timestamp.new timestamp.json
```
