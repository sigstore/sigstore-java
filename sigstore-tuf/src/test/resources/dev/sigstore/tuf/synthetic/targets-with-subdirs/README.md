# Setup test data

```shell
tuf init
tuf gen-key --expires=90 --scheme="ecdsa-sha2-nistp256" root
tuf gen-key --expires=90 --scheme="ecdsa-sha2-nistp256" targets
tuf gen-key --expires=90 --scheme="ecdsa-sha2-nistp256" snapshot
tuf gen-key --expires=90 --scheme="ecdsa-sha2-nistp256" timestamp
mkdir -p staged/targets/subdir
echo "test file" > staged/targets/subdir/test.txt
tuf add "subdir/test.txt"
tuf snapshot --expires=60
tuf timestamp --expires=30
tuf commit
```
