# Legacy compatibility fixtures

`legacy-cert.txt` and `legacy-sign.txt` were generated with the library before
the certificate/signature fixes, using the existing test `cert_with_key.pfx`.
Both contain the bytes 0 through 255, in order. These are test data, not secrets.

Keep these files frozen: recreating them with the code under test would weaken
the regression check. The certificate record preserves the old 32-byte salt
metadata (the first 16 bytes are the AES IV), 20-byte random password padded
to a 32-byte AES key, and RSA-OAEP-SHA1 wrapping. The signature is RSA PKCS#1 v1.5
with SHA-256. Both retain the old semicolon-separated thumbprint field.

`legacy-aes.txt` was generated before adding authenticated AES, using the existing
`GetAesCryptoString` with password `legacy AES password` and bytes 0 through 255.

`authenticated-aes-v1.txt` is an independent test vector, created without calling
Vespertan: .NET `Rfc2898DeriveBytes` with explicit HMAC-SHA256, 600000 iterations,
and 64 derived bytes, then `Aes` CBC/PKCS7 with the first 32 bytes and HMAC-SHA256
with the last 32 bytes. Plaintext is bytes 0 through 255, salt is bytes 0 through
15, IV is bytes 16 through 31. Password is UTF-8 `zażółć 🔐`, followed by one NUL
character, followed by `password`. The HMAC is computed in one call over ASCII
`$AesAuthenticated$` concatenated with the 37-byte header and ciphertext. The
header starts with bytes `01 00 09 27 c0`. Append the full 32-byte tag and Base64
encode the envelope. These fixed salt/IV values are for testing only; the public
writer always generates fresh random values.
