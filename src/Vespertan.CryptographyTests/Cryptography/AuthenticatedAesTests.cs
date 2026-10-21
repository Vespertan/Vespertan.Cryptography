using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Vespertan.Cryptography.Tests
{
    [TestClass]
    public class AuthenticatedAesTests
    {
        private const string Prefix = "$AesAuthenticated$";
        private const string VectorPassword = "zażółć 🔐\0password";

        [TestMethod]
        public void DecryptsIndependentVersionOneVectorThroughAllEntryPoints()
        {
            var record = Fixture("authenticated-aes-v1.txt");
            var expected = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            var passwordBytes = Encoding.UTF8.GetBytes(VectorPassword);
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptAuthenticatedAesData(record, VectorPassword));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptAesData(record, VectorPassword));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptAesData(record, passwordBytes));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(record, VectorPassword));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(record, VectorPassword, null));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(record, passwordBytes));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(record, passwordBytes, null));
            Assert.IsTrue(CryptoStrings.IsValidCryptoString(record));
            var parts = CryptoStrings.GetHashParts(record);
            Assert.AreEqual(CryptoType.AesAuthenticated, parts.Type);
            Assert.IsNull(parts.Data);
            CollectionAssert.AreEqual(Payload(record), parts.Hash);
        }

        [DataTestMethod]
        [DataRow("")]
        [DataRow("Zażółć gęślą jaźń 🔐\0koniec")]
        [DataRow("0123456789abcdef")]
        public void RoundTripsUtf8TextAndRandomizesEveryRecord(string text)
        {
            var first = CryptoStrings.GetAuthenticatedAesCryptoString(text, VectorPassword);
            var second = CryptoStrings.GetAuthenticatedAesCryptoString(text, VectorPassword);
            Assert.AreNotEqual(first, second);
            var firstBytes = Payload(first);
            var secondBytes = Payload(second);
            Assert.AreEqual(1, firstBytes[0]);
            CollectionAssert.AreEqual(new byte[] { 0, 9, 39, 192 }, firstBytes.Skip(1).Take(4).ToArray());
            Assert.IsFalse(firstBytes.Skip(5).Take(16).SequenceEqual(secondBytes.Skip(5).Take(16)));
            Assert.IsFalse(firstBytes.Skip(21).Take(16).SequenceEqual(secondBytes.Skip(21).Take(16)));
            Assert.AreEqual(text, CryptoStrings.DecryptAuthenticatedAesText(first, VectorPassword));
            Assert.AreEqual(text, CryptoStrings.DecryptAesText(first, VectorPassword));
            Assert.AreEqual(text, CryptoStrings.DecryptAesText(first, Encoding.UTF8.GetBytes(VectorPassword)));
            Assert.AreEqual(text, CryptoStrings.DecryptText(first, VectorPassword));
            Assert.AreEqual(text, CryptoStrings.DecryptText(first, Encoding.UTF8.GetBytes(VectorPassword)));
            Assert.AreEqual(text, CryptoStrings.DecryptAuthenticatedAesText(second, VectorPassword));
        }

        [DataTestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(15)]
        [DataRow(16)]
        [DataRow(17)]
        [DataRow(255)]
        public void RoundTripsBinaryDataAtPaddingBoundariesWithoutModifyingCallerBuffer(int length)
        {
            var data = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
            var original = (byte[])data.Clone();
            var record = CryptoStrings.GetAuthenticatedAesCryptoString(data, "password");
            CollectionAssert.AreEqual(original, data);
            CollectionAssert.AreEqual(original, CryptoStrings.DecryptAuthenticatedAesData(record, "password"));
            Assert.AreEqual(37 + ((length / 16) + 1) * 16 + 32, Payload(record).Length);
        }

        [TestMethod]
        public void RejectsWrongPasswordAndChangesToEveryAuthenticatedField()
        {
            var record = Fixture("authenticated-aes-v1.txt");
            AssertAuthenticationFailure(record, "wrong password");
            var payload = Payload(record);
            // Iterations (600001), both ends of salt and IV, data blocks and padding block.
            foreach (var index in new[] { 4, 5, 20, 21, 36, 37, 52, payload.Length - 33 })
            {
                var changed = (byte[])payload.Clone();
                changed[index] ^= 1;
                AssertAuthenticationFailure(Record(changed), VectorPassword);
            }
            for (var index = payload.Length - 32; index < payload.Length; index++)
            {
                var changed = (byte[])payload.Clone();
                changed[index] ^= 1;
                AssertAuthenticationFailure(Record(changed), VectorPassword);
            }
        }

        [TestMethod]
        public void DoesNotFallbackOrExposePaddingErrorsThroughExistingDecryptors()
        {
            var payload = Payload(Fixture("authenticated-aes-v1.txt"));
            Array.Clear(payload, 37, payload.Length - 37 - 32);
            var damaged = Record(payload);
            var passwordBytes = Encoding.UTF8.GetBytes(VectorPassword);
            AssertAuthenticationFailure(damaged, VectorPassword);
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAesData(damaged, VectorPassword));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAesData(damaged, passwordBytes));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAesText(damaged, VectorPassword));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptData(damaged, VectorPassword));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptData(damaged, passwordBytes));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptText(damaged, VectorPassword));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptText(damaged, passwordBytes));
        }

        [DataTestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(599999)]
        [DataRow(2000001)]
        [DataRow(int.MaxValue)]
        [DataRow(-1)]
        public void RejectsOutOfRangeWorkFactorsBeforeDerivation(int iterations)
        {
            var payload = Payload(Fixture("authenticated-aes-v1.txt"));
            payload[1] = (byte)(iterations >> 24);
            payload[2] = (byte)(iterations >> 16);
            payload[3] = (byte)(iterations >> 8);
            payload[4] = (byte)iterations;
            AssertMalformed(Record(payload));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                CryptoStrings.GetAuthenticatedAesCryptoString("text", "password", iterations));
        }

        [TestMethod]
        public void RejectsVersionsNonCanonicalEncodingTruncationAndExtraFields()
        {
            var record = Fixture("authenticated-aes-v1.txt");
            var payload = Payload(record);
            foreach (byte version in new byte[] { 0, 2, 255 })
            {
                var changed = (byte[])payload.Clone();
                changed[0] = version;
                AssertMalformed(Record(changed));
            }
            foreach (var length in new[] { 0, 1, 36, 37, 68, 69, 84, payload.Length - 1 })
                AssertMalformed(Record(payload.Take(length).ToArray()));
            AssertMalformed(Prefix + "!");
            AssertMalformed(record + "$extra");
            AssertMalformed(record + "\n");
            AssertMalformed(record.ToLowerInvariant());
            AssertMalformed(Prefix + " " + record.Substring(Prefix.Length));
            AssertMalformed(Record(payload.Concat(new byte[] { 0 }).ToArray()));
            // Whole-block removal/addition is still structurally valid, but must fail authentication.
            AssertAuthenticationFailure(Record(payload.Take(payload.Length - 16).ToArray()), VectorPassword);
            AssertAuthenticationFailure(Record(payload.Concat(new byte[16]).ToArray()), VectorPassword);
            // Changing unused Base64 pad bits must be rejected.
            var chars = record.ToCharArray();
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var lastDataCharacter = record.TrimEnd('=').Length - 1;
            chars[lastDataCharacter] = alphabet[alphabet.IndexOf(chars[lastDataCharacter]) + 1];
            AssertMalformed(new string(chars));
        }

        [TestMethod]
        public void PreservesFullPasswordsIncludingNulAndRejectsInvalidUnicode()
        {
            var password = new string('x', 10000) + "\0tail";
            var record = CryptoStrings.GetAuthenticatedAesCryptoString("text", password);
            Assert.AreEqual("text", CryptoStrings.DecryptAuthenticatedAesText(record, password));
            AssertAuthenticationFailure(record, new string('x', 10000));
            Assert.ThrowsException<EncoderFallbackException>(() =>
                CryptoStrings.GetAuthenticatedAesCryptoString("text", "\ud800"));
            Assert.ThrowsException<EncoderFallbackException>(() => CryptoStrings.DecryptData(record, "\ud800"));
            Assert.ThrowsException<DecoderFallbackException>(() => CryptoStrings.DecryptData(record, new byte[] { 255 }));
            Assert.ThrowsException<EncoderFallbackException>(() =>
                CryptoStrings.GetAuthenticatedAesCryptoString("\ud800", "password"));
        }

        [TestMethod]
        public void EnforcesMessageSizeLimitAndSupportsItsBoundary()
        {
            var data = new byte[CryptoStrings.MaximumAuthenticatedAesPlaintextLength];
            data[data.Length - 1] = 255;
            var record = CryptoStrings.GetAuthenticatedAesCryptoString(data, "password");
            Assert.IsTrue(data.SequenceEqual(CryptoStrings.DecryptAuthenticatedAesData(record, "password")));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                CryptoStrings.GetAuthenticatedAesCryptoString(new byte[data.Length + 1], "password"));
            AssertMalformed(record + "AAAA");
        }

        [TestMethod]
        public void SupportsMaximumWorkFactorAndEmptyPassword()
        {
            var record = CryptoStrings.GetAuthenticatedAesCryptoString("text", "", 2000000);
            Assert.AreEqual("text", CryptoStrings.DecryptAuthenticatedAesText(record, ""));
        }

        [TestMethod]
        public void RejectsNullInputs()
        {
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.GetAuthenticatedAesCryptoString((string)null, "p"));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.GetAuthenticatedAesCryptoString((byte[])null, "p"));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.GetAuthenticatedAesCryptoString("data", null));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.DecryptAuthenticatedAesData(null, "p"));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.DecryptAuthenticatedAesData(Fixture("authenticated-aes-v1.txt"), null));
        }

        [TestMethod]
        public void ReadsLegacyCiphertextAndCanMigrateItWithoutAllowingLegacyInStrictReader()
        {
            var old = Fixture("legacy-aes.txt");
            const string password = "legacy AES password";
            var expected = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptAesData(old, password));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptAesData(old, Encoding.UTF8.GetBytes(password)));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(old, password));
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptData(old, Encoding.UTF8.GetBytes(password)));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAuthenticatedAesData(old, password));
            var migrated = CryptoStrings.GetAuthenticatedAesCryptoString(CryptoStrings.DecryptData(old, password), password);
            CollectionAssert.AreEqual(expected, CryptoStrings.DecryptAuthenticatedAesData(migrated, password));
        }

        private static void AssertAuthenticationFailure(string record, string password)
        {
            var error = Assert.ThrowsException<CryptographicException>(() =>
                CryptoStrings.DecryptAuthenticatedAesData(record, password));
            Assert.AreEqual("Invalid authenticated AES record or password.", error.Message);
            Assert.IsNull(error.InnerException);
        }

        private static void AssertMalformed(string record)
        {
            AssertAuthenticationFailure(record, VectorPassword);
            Assert.IsFalse(CryptoStrings.IsValidCryptoString(record));
            Assert.ThrowsException<FormatException>(() => CryptoStrings.GetHashParts(record));
        }

        private static string Record(byte[] payload) => Prefix + Convert.ToBase64String(payload);
        private static byte[] Payload(string record) => Convert.FromBase64String(record.Substring(Prefix.Length));
        private static string Fixture(string filename) => File.ReadAllText(Path.Combine("Fixtures", filename));
    }
}
