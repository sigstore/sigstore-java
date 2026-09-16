# Setup test data

```shell
cp ../test-template/2.root.json 2.root.json
```

edit the values of signatures so they are wrong, but still match the threshold
```diff
  "signatures": [
    {
      "keyid": "0b5108e406f6d2f59ef767797b314be99d35903950ba43a2d51216eeeb8da98c",
+      "sig": "abcd123"
-      "sig": "304502204ee7d150bbbf40dc641d1a208be4708be14022da6a86883d2c5a7282eda2659802210095a15450c1e63ff20bd5164979007fbea8a7deea68ebba7a67f8cd2901b686ca"
    },
```
