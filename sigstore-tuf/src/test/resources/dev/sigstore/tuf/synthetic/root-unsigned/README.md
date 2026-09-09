# Setup test data

```shell
cp ../test-template/2.root.json .
## remove sigs
jq -r '.signatures |= []' 2.root.json > 2.root.json.new
rm 2.root.json && mv 2.root.json.new 2.root.json
```
