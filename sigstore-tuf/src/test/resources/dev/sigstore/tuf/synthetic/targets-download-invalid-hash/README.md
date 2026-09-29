# Setup test data

```shell
cp ../test-template/2.root.json .
cp ../test-template/timestamp.json .
cp ../test-template/3.snapshot.json .
cp ../test-template/3.targets.json .
mkdir targets
cp ../test-template/targets/860de8f9a858eea7190fcfa1b53fe55914d3c38f17f8f542273012d19cc9509bb423f37b7c13c577a56339ad7f45273b479b1d0df837cb6e20a550c27cce0885.test.txt targets/.
# Modify test.txt target so has is invalid
cat targets/860de8f9a858eea7190fcfa1b53fe55914d3c38f17f8f542273012d19cc9509bb423f37b7c13c577a56339ad7f45273b479b1d0df837cb6e20a550c27cce0885.test.txt | tr 'f' 'm' | sponge targets/860de8f9a858eea7190fcfa1b53fe55914d3c38f17f8f542273012d19cc9509bb423f37b7c13c577a56339ad7f45273b479b1d0df837cb6e20a550c27cce0885.test.txt
```
