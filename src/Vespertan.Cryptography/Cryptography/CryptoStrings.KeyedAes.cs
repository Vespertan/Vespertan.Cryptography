using System;
using System.Security.Cryptography;
using System.Text;

namespace Vespertan.Cryptography
{
    public static partial class CryptoStrings
    {
        public const int AuthenticatedAesKeyLength = 64;
        public const int MaximumAuthenticatedAesAssociatedDataLength = 18 * 1024 * 1024;
        private static readonly byte[] KeyedAesDomain = Encoding.ASCII.GetBytes("Vespertan.KeyedAes.v1\0");

        /// <summary>Generates independent AES-256 and HMAC-SHA256 keys. The caller must clear the returned 64 bytes.</summary>
        public static byte[] GenerateAuthenticatedAesKey() => GetRandomBytes(AuthenticatedAesKeyLength);

        /// <summary>Encrypts with a random IV and authenticates the envelope and exact associated data.</summary>
        /// <remarks>Key must be 64 random bytes, never a password. Inputs are borrowed and must not be mutated concurrently.</remarks>
        public static byte[] EncryptAuthenticatedAesWithKey(byte[] data, byte[] key, byte[] associatedData)
        {
            CheckKeyedArguments(data, key, associatedData);
            if (data.Length > MaximumAuthenticatedAesPlaintextLength) throw new ArgumentOutOfRangeException(nameof(data));
            var encryptionKey = new byte[32];
            var macKey = new byte[32];
            Buffer.BlockCopy(key, 0, encryptionKey, 0, 32);
            Buffer.BlockCopy(key, 32, macKey, 0, 32);
            try
            {
                var iv = GetRandomBytes(16);
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using var transform = aes.CreateEncryptor(encryptionKey, iv);
                var encrypted = transform.TransformFinalBlock(data, 0, data.Length);
                var result = new byte[17 + encrypted.Length + 32];
                result[0] = 1;
                Buffer.BlockCopy(iv, 0, result, 1, 16);
                Buffer.BlockCopy(encrypted, 0, result, 17, encrypted.Length);
                var tag = KeyedTag(result, result.Length - 32, macKey, associatedData);
                Buffer.BlockCopy(tag, 0, result, result.Length - 32, 32);
                return result;
            }
            finally
            {
                Array.Clear(encryptionKey, 0, encryptionKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        /// <summary>Authenticates before decrypting. Caller owns and must clear the returned plaintext.</summary>
        public static byte[] DecryptAuthenticatedAesWithKey(byte[] data, byte[] key, byte[] associatedData)
        {
            CheckKeyedArguments(data, key, associatedData);
            if (data.Length < 65 || data.Length > MaximumAuthenticatedAesPlaintextLength + 65 ||
                (data.Length - 49) % 16 != 0 || data[0] != 1)
                throw new CryptographicException("Invalid keyed AES record.");
            var encryptionKey = new byte[32];
            var macKey = new byte[32];
            Buffer.BlockCopy(key, 0, encryptionKey, 0, 32);
            Buffer.BlockCopy(key, 32, macKey, 0, 32);
            try
            {
                var expected = new byte[32];
                Buffer.BlockCopy(data, data.Length - 32, expected, 0, 32);
                if (!ArraysEquals(expected, KeyedTag(data, data.Length - 32, macKey, associatedData)))
                    throw new CryptographicException("Invalid keyed AES record.");
                var iv = new byte[16];
                Buffer.BlockCopy(data, 1, iv, 0, 16);
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using var transform = aes.CreateDecryptor(encryptionKey, iv);
                var result = transform.TransformFinalBlock(data, 17, data.Length - 49);
                if (result.Length <= MaximumAuthenticatedAesPlaintextLength) return result;
                Array.Clear(result, 0, result.Length);
                throw new CryptographicException("Invalid keyed AES record.");
            }
            catch (CryptographicException)
            {
                // Keep authenticated malformed padding and authentication failures provider-independent.
                throw new CryptographicException("Invalid keyed AES record.");
            }
            finally
            {
                Array.Clear(encryptionKey, 0, encryptionKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        private static void CheckKeyedArguments(byte[] data, byte[] key, byte[] associatedData)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (associatedData == null) throw new ArgumentNullException(nameof(associatedData));
            if (key.Length != AuthenticatedAesKeyLength) throw new ArgumentException("Key must contain 64 random bytes.", nameof(key));
            if (associatedData.Length > MaximumAuthenticatedAesAssociatedDataLength) throw new ArgumentOutOfRangeException(nameof(associatedData));
        }

        private static byte[] KeyedTag(byte[] record, int count, byte[] macKey, byte[] aad)
        {
            // A length prefix makes the AAD/envelope boundary unambiguous. All lengths are public.
            var length = new[] { (byte)(aad.Length >> 24), (byte)(aad.Length >> 16), (byte)(aad.Length >> 8), (byte)aad.Length };
            using var hmac = new HMACSHA256(macKey);
            hmac.TransformBlock(KeyedAesDomain, 0, KeyedAesDomain.Length, null, 0);
            hmac.TransformBlock(length, 0, length.Length, null, 0);
            hmac.TransformBlock(aad, 0, aad.Length, null, 0);
            hmac.TransformFinalBlock(record, 0, count);
            return hmac.Hash;
        }
    }
}
