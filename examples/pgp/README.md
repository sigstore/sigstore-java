## PGP test keys for examples

```
$ gpg --quick-gen-key "Test Key (DO NOT USE) <test@example.com>" rsa1024 sign never

passphrase:pass123

$ gpg --output private.key --armor --export-secret-key test@example.com
$ gpg --output public.key --armor --export test@example.com 
```
