# Vespertan.Cryptography

Helpers for crypto strings targeting .NET Framework 4.8 and .NET 10.0.
The library has no NuGet package dependencies. Existing serialized data formats
are shared by both targets; applications on later .NET versions can use the
`net10.0` library asset.

## Password storage with PBKDF2

```csharp
// Store the entire record, including its salt and parameters.
string stored = CryptoStrings.GetPbkdf2CryptoString(password);

// Load stored from your trusted password database, not from the login request.
bool valid = CryptoStrings.ValidatePasswordString(candidatePassword, stored);
// Alternatively, for PBKDF2 records only, use VerifyPbkdf2CryptoString.

// Upgrade old algorithms or a lower work factor only after successful login.
if (valid && CryptoStrings.NeedsPbkdf2Rehash(stored))
{
    string replacement = CryptoStrings.GetPbkdf2CryptoString(candidatePassword);
    // Persist replacement atomically in place of stored.
}
```

PBKDF2 uses HMAC-SHA-256, 600,000 iterations by default, a fresh 16-byte
cryptographically random salt, and a 32-byte derived key. New password records
require 600,000 through 2,000,000 iterations. To increase the cost, pass the
`iterations` argument to generation and `NeedsPbkdf2Rehash`. Measure login latency
and concurrency on the deployment host before choosing a cost. The default follows
the [OWASP PBKDF2 guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).

PBKDF2 uses explicit SHA-256 through built-in providers: `Rfc2898DeriveBytes`
on .NET Framework 4.8 and the static `Rfc2898DeriveBytes.Pbkdf2` on .NET 10.0.
The low-level API historically accepts salts shorter than eight bytes, which
Framework's constructor rejects; for those salts only, the `net48` build calls
Windows' built-in `BCryptDeriveKeyPBKDF2`. The PBKDF2 primitive is not implemented
by this library. Strict UTF-8 bytes and all existing parameters remain identical.
Framework's managed KDF may be substantially slower than the previous Windows
provider; measure operation latency on deployment hardware without lowering the
work factor below the supported minimum.

### Record format and validation

```text
$Pbkdf2$<Base64 derived key>$1;SHA256;<decimal iterations>;<Base64 salt>
```

`1` identifies the record format version. This is a Vespertan format, not an
ASP.NET Identity or PHC record. The type name is case-insensitive; other fields
are strict. Numbers have no signs, spaces or leading zeroes; Base64 is canonical.
Unknown versions/PRFs, extra fields, hashes other than 32 bytes, salts outside
16..64 bytes, and records longer than 160 characters are rejected. Verification
accepts 1..2,000,000 iterations to allow upgrading weaker imported records, while
generation enforces the stronger minimum. No fallback to another algorithm occurs.

`VerifyPbkdf2CryptoString` returns `false` for null passwords, null/malformed
records, ill-formed Unicode and password mismatches. Operational cryptography
errors are not suppressed. Generation throws argument exceptions for invalid
parameters and `EncoderFallbackException` for ill-formed Unicode. Empty passwords
are supported; password policy belongs to the application. Passwords are encoded
as UTF-8 without trimming, normalization or truncation. Embedded NULs are preserved.

`ValidatePasswordString` also supports the existing legacy formats. Its legacy
parsing/exception behavior is unchanged; use the dedicated verifier when accepting
PBKDF2 only. `NeedsPbkdf2Rehash` returns `true` for legacy, invalid, or lower-cost
records. It never verifies a password.

`GetHashParts` returns the derived key in `Hash` and the entire semicolon-separated
metadata in `Data`; `DataAsByteArray` is not applicable to PBKDF2. As with the existing
hash types, `DecryptData` only extracts the derived key. PBKDF2 is one-way and does
not recover the password.

### Low-level derivation

`HashPbkdf2(password, salt, iterations)` returns 32 raw bytes. It permits 1..64 salt
bytes and 1..2,000,000 iterations for interoperability and test vectors. These
minimums are **not password-storage recommendations**; prefer
`GetPbkdf2CryptoString` for password storage. Clear returned key bytes when finished.
The overload accepting an explicit salt requires a unique random salt for each
password. Prefer the overload generating the salt automatically.

### Security boundaries

- Rate-limit login attempts and bound request/password sizes in the application.
  The iteration ceiling bounds one derivation; it does not prevent request floods.
- Protect stored verifier records against modification and never log passwords.
  Temporary derived-key arrays are cleared, but .NET strings cannot be reliably erased.
- MD5, SHA-1 and plain SHA-2 (including salted variants) are legacy password formats.
  Migrate them after successful authentication. `None` and `NoneData` are plaintext
  or reversible encodings, not password protection.
- Legacy `EncryptAes` / `GetAesCryptoString` and certificate encryption do not
  authenticate ciphertext. For new password-based encryption use the authenticated
  format below. See the [security and correctness review](SECURITY_REVIEW.md).

## Authenticated AES encryption

```csharp
string record = CryptoStrings.GetAuthenticatedAesCryptoString(text, password);
string recovered = CryptoStrings.DecryptAuthenticatedAesText(record, password);

// Binary data has corresponding overloads:
string binaryRecord = CryptoStrings.GetAuthenticatedAesCryptoString(bytes, password);
byte[] recoveredBytes = CryptoStrings.DecryptAuthenticatedAesData(binaryRecord, password);

// During migration, existing readers support both the old and new AES formats:
byte[] plaintext = CryptoStrings.DecryptAesData(storedRecord, password);
try
{
    string upgradedRecord = CryptoStrings.GetAuthenticatedAesCryptoString(plaintext, password);
    // Persist upgradedRecord atomically after successful decryption.
}
finally
{
    Array.Clear(plaintext, 0, plaintext.Length);
}
```

The new format combines **AES-256-CBC/PKCS7 with HMAC-SHA256 using encrypt-then-MAC**.
This supports both target frameworks without implementing a cipher
or KDF primitive. PBKDF2-HMAC-SHA256 derives 64 bytes: the first 32 are the AES key,
and the remaining 32 are the HMAC key. The default is 600,000 iterations; creation
and reading accept 600,000..2,000,000. Override the creation cost with the optional
`iterations` argument. Deriving 64 bytes requires two PBKDF2 blocks, so benchmark this separately
from the 32-byte password verifier. Every encryption generates an independent
16-byte random salt and 16-byte random IV. Neither can be supplied by callers.

HMAC covers the format identifier, version, work factor, salt, IV, and the entire
ciphertext. The tag is compared without an early exit on a differing byte, **before
creating the AES decryptor or examining padding**. Temporary key arrays are cleared.
The construction follows the [OWASP encrypt-then-MAC guidance for platforms without
authenticated cipher modes](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes).

### Version 1 wire format

```text
$AesAuthenticated$<canonical Base64 envelope>
```

| Envelope offset | Size | Meaning |
| --- | --- | --- |
| 0 | 1 byte | Version: `01` (PBKDF2-SHA256 + AES-256-CBC/PKCS7 + HMAC-SHA256) |
| 1 | 4 bytes | Iterations, unsigned big-endian |
| 5 | 16 bytes | PBKDF2 salt |
| 21 | 16 bytes | AES IV |
| 37 | N bytes | Ciphertext; nonempty multiple of 16 |
| 37 + N | 32 bytes | Full HMAC-SHA256 tag |

HMAC input is ASCII bytes of `$AesAuthenticated$` followed by envelope bytes
`[0, 37 + N)` (everything except the tag). The prefix is case-sensitive. No
whitespace, extra fields, or noncanonical Base64 are accepted. Unknown versions,
invalid work factors, invalid lengths, and records exceeding the size cap are
rejected before deriving keys. Plaintext is limited to **16 MiB**; this is an
in-memory record API, not a file-streaming API.

Passwords are strict UTF-8, with no trimming, normalization, or truncation.
Empty passwords are supported but applications should require strong secrets.
The existing readers' `byte[] password` overloads interpret passwords as strict
UTF-8 **for this new format only**. Legacy byte passwords retain their original
meaning. Malformed Unicode throws an encoding exception. Text creation and the
dedicated text reader also use strict UTF-8; use binary APIs for arbitrary bytes.

`DecryptAuthenticatedAesData` / `DecryptAuthenticatedAesText` accept only this
format. Wrong passwords, invalid tags and malformed records throw
`CryptographicException`; null arguments throw `ArgumentNullException`. Readers
never retry the legacy format after an authentication failure. `DecryptAesData`,
`DecryptAesText`, `DecryptData`, and `DecryptText` dispatch by record type and retain
legacy compatibility. Once migration is complete, prefer the dedicated readers
so an attacker cannot substitute an unauthenticated legacy record.

`IsValidCryptoString` checks syntax, lengths and supported parameters, **not the
HMAC**. Only successful authenticated decryption proves integrity. For this type,
`GetHashParts().Hash` is the entire binary envelope and `Data` is null.

Existing `GetAesCryptoString` / `EncryptAes` overloads still write their original
legacy format for compatibility; switch writers explicitly to
`GetAuthenticatedAesCryptoString`. No stored data is automatically rewritten.
Old AES and `Cert` records still lack integrity protection. Migration cannot
establish whether old ciphertext was tampered with before it was read.

Limit concurrent decryption attempts and request sizes in the application.
Authentication does not prevent replay, rollback, or substitution of a different
valid record encrypted with the same password; bind application identity/context
inside the plaintext and verify it when needed. Password strength still determines
resistance to offline guessing. Stored ciphertext needs no secret salt or IV.

## Authenticated encryption with an existing random key

`GenerateAuthenticatedAesKey()` returns 64 random bytes (separate 32-byte AES
and HMAC keys). `EncryptAuthenticatedAesWithKey(data, key, associatedData)` and
`DecryptAuthenticatedAesWithKey(record, key, associatedData)` support the same
wire format on net48 and net10.0. A fresh random IV is generated on every write.
Use a generated key, never a password or a padded password. Inputs are borrowed,
not modified, and must not be changed concurrently. Clear owned keys and returned
plaintext when finished.

The binary envelope is `version=01 (1) || IV (16) || AES-256-CBC/PKCS7 ciphertext
(positive multiple of 16) || HMAC-SHA256 (32)`. HMAC input is ASCII
`Vespertan.KeyedAes.v1\0`, followed by the AAD length as UInt32 big-endian,
the exact AAD, and the envelope excluding its tag. The trailing `\0` in the domain
is one NUL byte. Authentication is checked before AES decryption; the keys are
independent halves of the random 64-byte key. This is the same encrypt-then-MAC
construction used above, with domain separation and AAD instead of password KDF.

Maximum plaintext is 16 MiB, maximum AAD 18 MiB. Empty plaintext/AAD are allowed.
Wrong tags, unsupported versions and malformed records throw
`CryptographicException` with the fixed message `Invalid keyed AES record.`
(including authenticated records with invalid padding); invalid API arguments
throw argument exceptions. No
fallback or automatic format dispatch occurs. This new binary API does not
change any existing string API or serialized format. Context binding and
replay/rollback protection remain application responsibilities.

This construction does not promise key commitment if callers deliberately share
the HMAC half between different AES keys. Generate a fresh complete key for each
independent context; do not construct keys by reusing individual halves.

## Certificates and signatures

Existing `$Cert$` and `$Sign$` records remain readable. Certificate encryption
retains the original AES-CBC payload, RSA-OAEP-SHA1 wrapped key, and metadata
layout. Signatures retain RSA PKCS#1 v1.5 with SHA-256. No data migration is needed
for these fixes.

```csharp
using (var privateKey = recipientCertificate.GetRSAPrivateKey())
{
    byte[] plaintext = CryptoStrings.DecryptData(encryptedRecord, privateKey);
    string text = CryptoStrings.DecryptText(encryptedRecord, (string)null, privateKey);
}

// A certificate containing only the public key is sufficient for verification.
bool verified = CryptoStrings.VerifySign(signedRecord, trustedSignerCertificate);
byte[] signedData = CryptoStrings.GetSignData(signedRecord, trustedSignerCertificate);
string signedText = CryptoStrings.GetSignText(signedRecord, trustedSignerCertificate);
```

`GetSignData` also accepts an `RSA` public key. It and `GetSignText` throw
`InvalidOperationException` on a signature mismatch; `VerifySign` returns `false`.
Wrong record types throw `InvalidOperationException`; malformed metadata can throw
`FormatException`. A public-only certificate cannot decrypt or create signatures.
RSA objects supplied by the caller are not disposed by these methods.

**Security behavior change:** `DecryptData` and `DecryptText` now verify `Sign`
records before returning their contents. Pass the trusted signer's RSA key through
the existing `privateKey` parameter (its name is retained for source compatibility;
only the public part is required for verification). A missing key is rejected.
For explicit **unverified extraction**, use `GetHashParts(record).Hash`.

The application must choose a trusted key/certificate. These methods verify the
signature cryptographically, without checking certificate chains, expiry or
revocation. The stored thumbprint is descriptive metadata, not proof of trust and
not covered by the signature. Existing certificate encryption still does not
authenticate ciphertext; the signature fixes do not add that property.

## Tests

```shell
dotnet test src/Vespertan.Cryptography.sln --configuration Release --filter FullyQualifiedName~Pbkdf2Tests
dotnet test src/Vespertan.Cryptography.sln --configuration Release
powershell -NoProfile -File tests/Test-CrossTargetCompatibility.ps1
```

Run the complete suite and the cross-target script on Windows with the .NET
Framework 4.8 targeting pack/runtime, the .NET 10 SDK, and the .NET 10
runtime. `dotnet test` runs the same unit tests on both targets. The `net10.0` suite
can also be selected independently with `--framework net10.0`.

The cross-target script builds a test-only console host twice, then launches it
in the two different runtimes. Each host writes 39 fresh records; the other must
read them successfully and reject tampering/wrong passwords. The exchange covers
PBKDF2 records, authenticated AES text/binary/empty payloads, legacy AES,
certificates, signatures, and raw PBKDF2 with salt lengths 1..16 and empty/nonempty
passwords. It fails on a nonzero process exit and removes its temporary exchange
files. It is separate from unit tests so running just one target does not silently
skip a missing second runtime.

Tests include RFC 7914 section 11 vectors (their first 32 bytes), independent UTF-8
fixtures, boundary parameters, malformed records, tampering, and legacy password
verification. Certificate/signature tests include frozen records generated before
the fixes, an independent legacy-format reader, public-key-only verification,
tampering, wrong keys and missing keys. Both targets read the same frozen fixtures.
Authenticated AES tests include an independently generated v1 fixture, a frozen
legacy AES fixture, migration, padding boundaries, all authenticated fields,
every tag byte, work/size limits, strict parsing, and the absence of legacy fallback.
