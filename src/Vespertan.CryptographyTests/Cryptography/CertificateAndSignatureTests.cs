using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Vespertan.Cryptography.Tests
{
    [TestClass]
    public class CertificateAndSignatureTests
    {
        private X509Certificate2 privateCertificate;
        private X509Certificate2 publicCertificate;
        private RSA privateKey;
        private RSA publicKey;

        [TestInitialize]
        public void Initialize()
        {
            privateCertificate = TestCertificates.LoadPrivate();
            publicCertificate = TestCertificates.LoadPublic();
            privateKey = privateCertificate.GetRSAPrivateKey();
            publicKey = publicCertificate.GetRSAPublicKey();
        }

        [TestCleanup]
        public void Cleanup()
        {
            privateKey?.Dispose();
            publicKey?.Dispose();
            privateCertificate?.Dispose();
            publicCertificate?.Dispose();
        }

        [TestMethod]
        public void DecryptsFrozenLegacyCertificateRecordThroughEveryDataOverload()
        {
            var record = Fixture("legacy-cert.txt");
            var expected = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            Assert.AreEqual(32, Convert.FromBase64String(record.Split('$')[3].Split(';')[0]).Length);
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptCertData(record, privateCertificate));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptCertData(record, privateKey));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(record, privateKey));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(record, (string)null, privateKey));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(record, (byte[])null, privateKey));
        }

        [TestMethod]
        public void VerifiesFrozenLegacySignatureWithPublicOnlyCertificateAndRsa()
        {
            var record = Fixture("legacy-sign.txt");
            var expected = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            Assert.IsFalse(publicCertificate.HasPrivateKey);
            Assert.IsTrue(CryptoStrings.VerifySign(record, publicCertificate));
            Assert.IsTrue(CryptoStrings.VerifySign(record, privateCertificate));
            Assert.IsTrue(CryptoStrings.VerifySign(record, publicKey));
            CollectionAssert.AreEqual(expected, CryptoStrings.GetSignData(record, publicCertificate));
            CollectionAssert.AreEqual(expected, CryptoStrings.GetSignData(record, privateCertificate));
            CollectionAssert.AreEqual(expected, CryptoStrings.GetSignData(record, publicKey));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(record, publicKey));
            // PKCS#1 v1.5 signatures are deterministic: keep the old serializer byte-for-byte.
            Assert.AreEqual(record, CryptoStrings.GetSignCryptoString(expected, privateKey, privateCertificate.Thumbprint));
        }

        [DataTestMethod]
        [DataRow("")]
        [DataRow("Zażółć gęślą jaźń 🔐\0koniec")]
        public void RoundTripsCertificateTextWithAndWithoutThumbprint(string text)
        {
            foreach (var record in new[]
            {
                CryptoStrings.GetCertCryptoString(text, publicCertificate),
                CryptoStrings.GetCertCryptoString(text, publicKey)
            })
            {
                Assert.AreEqual(text, CryptoStrings.DecryptCertText(record, privateCertificate));
                Assert.AreEqual(text, CryptoStrings.DecryptCertText(record, privateKey));
                Assert.AreEqual(text, CryptoStrings.DecryptText(record, (byte[])null, privateKey));
                Assert.AreEqual(text, CryptoStrings.DecryptText(record, (string)null, privateKey));
            }
        }

        [DataTestMethod]
        [DataRow("")]
        [DataRow("Zażółć gęślą jaźń 🔐\0koniec")]
        public void RoundTripsSignatureTextWithAndWithoutThumbprint(string text)
        {
            foreach (var record in new[]
            {
                CryptoStrings.GetSignCryptoString(text, privateCertificate),
                CryptoStrings.GetSignCryptoString(text, privateKey)
            })
            {
                Assert.IsTrue(CryptoStrings.VerifySign(record, publicCertificate));
                Assert.IsTrue(CryptoStrings.VerifySign(record, publicKey));
                Assert.AreEqual(text, CryptoStrings.GetSignText(record, publicCertificate));
                Assert.AreEqual(text, CryptoStrings.DecryptText(record, (string)null, publicKey));
                CollectionAssert.AreEqual(Encoding.UTF8.GetBytes(text), CryptoStrings.GetSignData(record, publicCertificate));
            }
        }

        [TestMethod]
        public void NewCertificateRecordsRemainReadableByLegacyAlgorithms()
        {
            var expected = Enumerable.Range(0, 4096).Select(i => (byte)i).ToArray();
            var record = CryptoStrings.GetCertCryptoString(expected, publicKey);
            var parts = record.Split('$');
            Assert.AreEqual("Cert", parts[1]);
            var metadata = parts[3].Split(';');
            Assert.AreEqual(3, metadata.Length);
            Assert.AreEqual("", metadata[2]);
            // Independent reader for the pre-fix AES-CBC + RSA-OAEP-SHA1 format.
            var wrappedKey = Convert.FromBase64String(metadata[1]);
            var legacyPassword = privateKey.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA1);
            Assert.AreEqual(20, legacyPassword.Length);
            var aesKey = new byte[32];
            Array.Copy(legacyPassword, aesKey, legacyPassword.Length);
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                var iv = Convert.FromBase64String(metadata[0]).Take(16).ToArray();
                using (var decryptor = aes.CreateDecryptor(aesKey, iv))
                {
                    var ciphertext = Convert.FromBase64String(parts[2]);
                    CollectionAssert.AreEqual(expected, decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length));
                }
            }
        }

        [TestMethod]
        public void RejectsChangedSignedDataAndSignatureBeforeReturningData()
        {
            var original = Fixture("legacy-sign.txt");
            var parts = original.Split('$');
            var data = Convert.FromBase64String(parts[2]);
            data[0] ^= 1;
            var changedData = "$Sign$" + Convert.ToBase64String(data) + "$" + parts[3];
            var metadata = parts[3].Split(';');
            var signature = Convert.FromBase64String(metadata[0]);
            signature[signature.Length - 1] ^= 1;
            var changedSignature = "$Sign$" + parts[2] + "$" + Convert.ToBase64String(signature) + ";" + metadata[1];

            foreach (var record in new[] { changedData, changedSignature })
            {
                Assert.IsFalse(CryptoStrings.VerifySign(record, publicCertificate));
                Assert.IsFalse(CryptoStrings.VerifySign(record, publicKey));
                Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.GetSignData(record, publicCertificate));
                Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.GetSignText(record, publicCertificate));
                Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.GetSignData(record, publicKey));
                Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.DecryptData(record, publicKey));
                Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.DecryptText(record, (byte[])null, publicKey));
            }
        }

        [TestMethod]
        public void RejectsWrongKeysAndDoesNotTrustThumbprintAsAuthentication()
        {
            using (var wrongKey = RSA.Create())
            {
                wrongKey.KeySize = 2048;
                var encrypted = Fixture("legacy-cert.txt");
                AssertCryptographicFailure(() => CryptoStrings.DecryptCertData(encrypted, wrongKey));
                AssertCryptographicFailure(() => CryptoStrings.DecryptData(encrypted, wrongKey));
                // Forged metadata cannot make an unrelated signature trusted.
                var signed = CryptoStrings.GetSignCryptoString("message", wrongKey, publicCertificate.Thumbprint);
                Assert.IsFalse(CryptoStrings.VerifySign(signed, publicCertificate));
                Assert.IsFalse(CryptoStrings.VerifySign(signed, publicKey));
                Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.GetSignText(signed, publicCertificate));
                Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.GetSignData(signed, publicCertificate));
                Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.DecryptData(signed, publicKey));
            }
        }

        [TestMethod]
        public void RejectsMissingKeysAndPublicOnlyCertificateForPrivateOperations()
        {
            var signed = Fixture("legacy-sign.txt");
            var encrypted = Fixture("legacy-cert.txt");
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.DecryptData(signed, (RSA)null));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.DecryptData(signed, "unused password"));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.DecryptText(signed, "unused password"));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.VerifySign(signed, (RSA)null));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.GetSignData(signed, (RSA)null));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.DecryptData(encrypted, (RSA)null));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptCertData(encrypted, publicCertificate));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.GetSignCryptoString("message", publicCertificate));
            // Explicit unverified extraction stays available and makes no authentication claim.
            Assert.AreEqual(256, CryptoStrings.GetHashParts(signed).Hash.Length);
        }

        private static void AssertCryptographicFailure(Action action)
        {
            // RSAOpenSsl reports a derived CryptographicException; MSTest v2 ThrowsException requires an exact type.
            try { action(); }
            catch (CryptographicException) { return; }
            Assert.Fail("The operation must reject the wrong RSA key with a cryptographic failure.");
        }

        [TestMethod]
        public void RejectsIncorrectRecordTypes()
        {
            var encrypted = Fixture("legacy-cert.txt");
            var signed = Fixture("legacy-sign.txt");
            Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.VerifySign(encrypted, publicCertificate));
            Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.VerifySign(encrypted, publicKey));
            Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.GetSignData(encrypted, publicCertificate));
            Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.GetSignText(encrypted, publicCertificate));
            Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.DecryptCertData(signed, privateCertificate));
            Assert.ThrowsException<InvalidOperationException>(() => CryptoStrings.DecryptCertText(signed, privateKey));
        }

        [DataTestMethod]
        [DataRow("$Sign$AA==")]
        [DataRow("$Sign$AA==$AA==")]
        [DataRow("$Sign$AA==$!;")]
        public void RejectsMalformedSignatureMetadata(string record)
        {
            Assert.ThrowsException<FormatException>(() => CryptoStrings.VerifySign(record, publicCertificate));
            Assert.ThrowsException<FormatException>(() => CryptoStrings.GetSignData(record, publicKey));
            Assert.ThrowsException<FormatException>(() => CryptoStrings.DecryptData(record, publicKey));
        }

        [DataTestMethod]
        [DataRow("$Cert$AA==")]
        [DataRow("$Cert$AA==$AA==")]
        [DataRow("$Cert$AA==$AA==;AA==")]
        [DataRow("$Cert$AA==$!;AA==;")]
        public void RejectsMalformedCertificateMetadata(string record)
        {
            Assert.ThrowsException<FormatException>(() => CryptoStrings.DecryptCertData(record, privateCertificate));
            Assert.ThrowsException<FormatException>(() => CryptoStrings.DecryptData(record, privateKey));
        }

        [TestMethod]
        public void KeepsCallerOwnedKeysUsableAfterOperations()
        {
            for (var i = 0; i < 2; i++)
            {
                var encrypted = CryptoStrings.GetCertCryptoString("message", publicKey);
                Assert.AreEqual("message", CryptoStrings.DecryptCertText(encrypted, privateKey));
                var signed = CryptoStrings.GetSignCryptoString("message", privateKey);
                Assert.IsTrue(CryptoStrings.VerifySign(signed, publicKey));
                CollectionAssert.AreEqual(Encoding.UTF8.GetBytes("message"), CryptoStrings.GetSignData(signed, publicKey));
            }
        }

        private static string Fixture(string filename)
        {
            return File.ReadAllText(Path.Combine("Fixtures", filename));
        }
    }
}
