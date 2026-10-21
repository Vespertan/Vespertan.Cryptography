using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Vespertan.Cryptography.Tests
{
    [TestClass]
    public class KeyedAesTests
    {
        [DataTestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(15)]
        [DataRow(16)]
        [DataRow(17)]
        [DataRow(4096)]
        public void RoundTripAndIndependentReader(int length)
        {
            var key = CryptoStrings.GenerateAuthenticatedAesKey();
            var data = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
            var aad = Encoding.UTF8.GetBytes("vault-01/contents");
            var encrypted = CryptoStrings.EncryptAuthenticatedAesWithKey(data, key, aad);
            CollectionAssert.AreEqual(data, CryptoStrings.DecryptAuthenticatedAesWithKey(encrypted, key, aad));
            CollectionAssert.AreEqual(data, ReferenceDecrypt(encrypted, key, aad));
            Assert.IsFalse(encrypted.SequenceEqual(CryptoStrings.EncryptAuthenticatedAesWithKey(data, key, aad)));
        }

        [TestMethod]
        public void EveryByteAndAssociatedDataAreAuthenticatedAndWrongKeysAreRejected()
        {
            var key = CryptoStrings.GenerateAuthenticatedAesKey();
            var aad = new byte[] { 1, 2, 3 };
            var record = CryptoStrings.EncryptAuthenticatedAesWithKey(new byte[32], key, aad);
            for (int i = 0; i < record.Length; i++)
            {
                var changed = (byte[])record.Clone();
                changed[i] ^= 1;
                Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAuthenticatedAesWithKey(changed, key, aad));
            }
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAuthenticatedAesWithKey(record, key, new byte[] { 1, 2, 4 }));
            // Wrong AES half can occasionally produce valid padding, so use an independent complete random key.
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAuthenticatedAesWithKey(record, CryptoStrings.GenerateAuthenticatedAesKey(), aad));
            key[32] ^= 1;
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAuthenticatedAesWithKey(record, key, aad));
        }

        [TestMethod]
        public void ValidatesBoundariesAndDoesNotMutateInputs()
        {
            var key = CryptoStrings.GenerateAuthenticatedAesKey();
            var saved = (byte[])key.Clone();
            var data = new byte[CryptoStrings.MaximumAuthenticatedAesPlaintextLength];
            var aad = Array.Empty<byte>();
            var record = CryptoStrings.EncryptAuthenticatedAesWithKey(data, key, aad);
            CollectionAssert.AreEqual(data, CryptoStrings.DecryptAuthenticatedAesWithKey(record, key, aad));
            CollectionAssert.AreEqual(saved, key);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.EncryptAuthenticatedAesWithKey(new byte[data.Length + 1], key, aad));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.EncryptAuthenticatedAesWithKey(aad, key, new byte[CryptoStrings.MaximumAuthenticatedAesAssociatedDataLength + 1]));
            Assert.ThrowsException<ArgumentException>(() => CryptoStrings.EncryptAuthenticatedAesWithKey(aad, new byte[32], aad));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.EncryptAuthenticatedAesWithKey(null, key, aad));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.EncryptAuthenticatedAesWithKey(aad, null, aad));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.DecryptAuthenticatedAesWithKey(aad, key, null));
            Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAuthenticatedAesWithKey(record.Take(record.Length - 1).ToArray(), key, aad));
        }

        [TestMethod]
        public void AuthenticatedInvalidPaddingHasTheSamePublicErrorAsInvalidTag()
        {
            var key = CryptoStrings.GenerateAuthenticatedAesKey();
            var aad = new byte[] { 1 };
            var record = CryptoStrings.EncryptAuthenticatedAesWithKey(Array.Empty<byte>(), key, aad);
            // Empty plaintext is one block of 0x10 padding. Alter the IV to force last byte 0x00.
            record[16] ^= 16;
            var input = Encoding.ASCII.GetBytes("Vespertan.KeyedAes.v1\0")
                .Concat(new byte[] { 0, 0, 0, 1 }).Concat(aad).Concat(record.Take(record.Length - 32)).ToArray();
            using (var hmac = new HMACSHA256(key.Skip(32).ToArray()))
                Buffer.BlockCopy(hmac.ComputeHash(input), 0, record, record.Length - 32, 32);
            var padding = Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAuthenticatedAesWithKey(record, key, aad));
            record[record.Length - 1] ^= 1;
            var tag = Assert.ThrowsException<CryptographicException>(() => CryptoStrings.DecryptAuthenticatedAesWithKey(record, key, aad));
            Assert.AreEqual("Invalid keyed AES record.", padding.Message);
            Assert.AreEqual(tag.Message, padding.Message);
            Assert.IsNull(padding.InnerException);
        }

        [TestMethod]
        public void AssociatedDataLimitsAndPublicParameterNames()
        {
            var key = CryptoStrings.GenerateAuthenticatedAesKey();
            var empty = Array.Empty<byte>();
            var aad = new byte[CryptoStrings.MaximumAuthenticatedAesAssociatedDataLength];
            var record = CryptoStrings.EncryptAuthenticatedAesWithKey(empty, key, aad);
            CollectionAssert.AreEqual(empty, CryptoStrings.DecryptAuthenticatedAesWithKey(record, key, aad));
            Assert.AreEqual("associatedData", Assert.ThrowsException<ArgumentNullException>(
                () => CryptoStrings.DecryptAuthenticatedAesWithKey(record, key, null)).ParamName);
            Assert.AreEqual("associatedData", Assert.ThrowsException<ArgumentOutOfRangeException>(
                () => CryptoStrings.EncryptAuthenticatedAesWithKey(empty, key, new byte[aad.Length + 1])).ParamName);
        }

        private static byte[] ReferenceDecrypt(byte[] record, byte[] key, byte[] aad)
        {
            byte[] prefix = Encoding.ASCII.GetBytes("Vespertan.KeyedAes.v1\0");
            var length = new byte[] { (byte)(aad.Length >> 24), (byte)(aad.Length >> 16), (byte)(aad.Length >> 8), (byte)aad.Length };
            var input = prefix.Concat(length).Concat(aad).Concat(record.Take(record.Length - 32)).ToArray();
            using (var hmac = new HMACSHA256(key.Skip(32).ToArray()))
                CollectionAssert.AreEqual(record.Skip(record.Length - 32).ToArray(), hmac.ComputeHash(input));
            using (var aes = Aes.Create())
            using (var decryptor = aes.CreateDecryptor(key.Take(32).ToArray(), record.Skip(1).Take(16).ToArray()))
                return decryptor.TransformFinalBlock(record, 17, record.Length - 49);
        }
    }
}
