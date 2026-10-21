using System;
using System.Security.Cryptography;
using System.Text;

namespace Vespertan.Cryptography
{
    public static partial class CryptoStrings
    {
        public const int MaximumAuthenticatedAesPlaintextLength = 16 * 1024 * 1024;
        internal const string AuthenticatedAesPrefix = "$AesAuthenticated$";
        private const int AuthenticatedAesHeaderLength = 37;
        private const int AuthenticatedAesTagLength = 32;
        private const int MaximumAuthenticatedAesPayloadLength =
            AuthenticatedAesHeaderLength + MaximumAuthenticatedAesPlaintextLength + 16 + AuthenticatedAesTagLength;
        private static readonly byte[] AuthenticatedAesDomain = Encoding.ASCII.GetBytes(AuthenticatedAesPrefix);
        private const string AuthenticatedAesFailure = "Invalid authenticated AES record or password.";

        /// <summary>Encrypts UTF-8 text with version 1 AES-256-CBC/HMAC-SHA256 and PBKDF2-HMAC-SHA256.</summary>
        public static string GetAuthenticatedAesCryptoString(string data, string password,
            int iterations = DefaultPbkdf2Iterations)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (Pbkdf2Utf8.GetByteCount(data) > MaximumAuthenticatedAesPlaintextLength)
                throw new ArgumentOutOfRangeException(nameof(data));
            var plaintext = Pbkdf2Utf8.GetBytes(data);
            try
            {
                return GetAuthenticatedAesCryptoString(plaintext, password, iterations);
            }
            finally
            {
                Array.Clear(plaintext, 0, plaintext.Length);
            }
        }

        /// <summary>Encrypts up to 16 MiB, generating a fresh 16-byte salt and independent 16-byte IV.</summary>
        /// <remarks>The supplied data is not modified. Iterations must be 600,000..2,000,000.</remarks>
        public static string GetAuthenticatedAesCryptoString(byte[] data, string password,
            int iterations = DefaultPbkdf2Iterations)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length > MaximumAuthenticatedAesPlaintextLength)
                throw new ArgumentOutOfRangeException(nameof(data));
            if (password == null) throw new ArgumentNullException(nameof(password));
            CheckPbkdf2Iterations(iterations, DefaultPbkdf2Iterations);
            Pbkdf2Utf8.GetByteCount(password);

            var salt = GetRandomBytes(16);
            var iv = GetRandomBytes(16);
            DeriveAuthenticatedAesKeys(password, salt, iterations, out var encryptionKey, out var macKey);
            try
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using var encryptor = aes.CreateEncryptor(encryptionKey, iv);
                var ciphertext = encryptor.TransformFinalBlock(data, 0, data.Length);
                var payload = new byte[AuthenticatedAesHeaderLength + ciphertext.Length + AuthenticatedAesTagLength];
                // v1: version(1), iterations(uint32 big endian), salt(16), IV(16), ciphertext, tag(32).
                payload[0] = 1;
                payload[1] = (byte)(iterations >> 24);
                payload[2] = (byte)(iterations >> 16);
                payload[3] = (byte)(iterations >> 8);
                payload[4] = (byte)iterations;
                Buffer.BlockCopy(salt, 0, payload, 5, 16);
                Buffer.BlockCopy(iv, 0, payload, 21, 16);
                Buffer.BlockCopy(ciphertext, 0, payload, AuthenticatedAesHeaderLength, ciphertext.Length);
                var tagOffset = payload.Length - AuthenticatedAesTagLength;
                var tag = ComputeAuthenticatedAesTag(payload, tagOffset, macKey);
                Buffer.BlockCopy(tag, 0, payload, tagOffset, tag.Length);
                return AuthenticatedAesPrefix + Convert.ToBase64String(payload);
            }
            finally
            {
                Array.Clear(encryptionKey, 0, encryptionKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        /// <summary>Decrypts only authenticated AES records, verifying the full envelope before AES decryption.</summary>
        /// <remarks>Never falls back to the legacy format. Wrong passwords or damaged records throw CryptographicException.</remarks>
        public static byte[] DecryptAuthenticatedAesData(string cryptoString, string password)
        {
            if (cryptoString == null) throw new ArgumentNullException(nameof(cryptoString));
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryReadAuthenticatedAes(cryptoString, out var payload, out var iterations))
                throw new CryptographicException(AuthenticatedAesFailure);
            Pbkdf2Utf8.GetByteCount(password);

            var salt = new byte[16];
            Buffer.BlockCopy(payload, 5, salt, 0, salt.Length);
            DeriveAuthenticatedAesKeys(password, salt, iterations, out var encryptionKey, out var macKey);
            try
            {
                var tagOffset = payload.Length - AuthenticatedAesTagLength;
                var expected = new byte[AuthenticatedAesTagLength];
                Buffer.BlockCopy(payload, tagOffset, expected, 0, expected.Length);
                var actual = ComputeAuthenticatedAesTag(payload, tagOffset, macKey);
                if (!ArraysEquals(actual, expected))
                    throw new CryptographicException(AuthenticatedAesFailure);

                // Do not create a decryptor or examine CBC padding until the tag has been verified.
                var iv = new byte[16];
                Buffer.BlockCopy(payload, 21, iv, 0, iv.Length);
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using var decryptor = aes.CreateDecryptor(encryptionKey, iv);
                var plaintext = decryptor.TransformFinalBlock(payload, AuthenticatedAesHeaderLength,
                    tagOffset - AuthenticatedAesHeaderLength);
                if (plaintext.Length > MaximumAuthenticatedAesPlaintextLength)
                {
                    Array.Clear(plaintext, 0, plaintext.Length);
                    throw new CryptographicException(AuthenticatedAesFailure);
                }
                return plaintext;
            }
            finally
            {
                Array.Clear(encryptionKey, 0, encryptionKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        /// <summary>Decrypts authenticated AES and decodes strict UTF-8 text.</summary>
        public static string DecryptAuthenticatedAesText(string cryptoString, string password)
        {
            var plaintext = DecryptAuthenticatedAesData(cryptoString, password);
            try
            {
                return Pbkdf2Utf8.GetString(plaintext);
            }
            finally
            {
                Array.Clear(plaintext, 0, plaintext.Length);
            }
        }

        private static void DeriveAuthenticatedAesKeys(string password, byte[] salt, int iterations,
            out byte[] encryptionKey, out byte[] macKey)
        {
            var material = DerivePbkdf2Sha256(password, salt, iterations, 64);
            try
            {
                encryptionKey = new byte[32];
                macKey = new byte[32];
                Buffer.BlockCopy(material, 0, encryptionKey, 0, 32);
                Buffer.BlockCopy(material, 32, macKey, 0, 32);
            }
            finally
            {
                Array.Clear(material, 0, material.Length);
            }
        }

        private static byte[] ComputeAuthenticatedAesTag(byte[] payload, int count, byte[] macKey)
        {
            using var hmac = new HMACSHA256(macKey);
            hmac.TransformBlock(AuthenticatedAesDomain, 0, AuthenticatedAesDomain.Length, null, 0);
            hmac.TransformBlock(payload, 0, count, null, 0);
            hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return hmac.Hash;
        }

        internal static bool UsesAuthenticatedAesFormat(string value)
        {
            return value != null && value.StartsWith(AuthenticatedAesPrefix, StringComparison.OrdinalIgnoreCase);
        }

        private static byte[] DecryptAuthenticatedAesFromUtf8(string value, byte[] password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return DecryptAuthenticatedAesData(value, Pbkdf2Utf8.GetString(password));
        }

        internal static bool TryReadAuthenticatedAes(string value, out byte[] payload, out int iterations)
        {
            payload = null;
            iterations = 0;
            var maximumTextLength = AuthenticatedAesPrefix.Length + ((MaximumAuthenticatedAesPayloadLength + 2) / 3) * 4;
            if (value == null || value.Length > maximumTextLength
                || !value.StartsWith(AuthenticatedAesPrefix, StringComparison.Ordinal)) return false;
            var base64 = value.Substring(AuthenticatedAesPrefix.Length);
            try
            {
                payload = Convert.FromBase64String(base64);
            }
            catch (FormatException)
            {
                return false;
            }
            if (payload.Length < AuthenticatedAesHeaderLength + 16 + AuthenticatedAesTagLength
                || payload.Length > MaximumAuthenticatedAesPayloadLength
                || (payload.Length - AuthenticatedAesHeaderLength - AuthenticatedAesTagLength) % 16 != 0
                || payload[0] != 1 || Convert.ToBase64String(payload) != base64) return false;

            uint work = ((uint)payload[1] << 24) | ((uint)payload[2] << 16)
                | ((uint)payload[3] << 8) | payload[4];
            if (work < DefaultPbkdf2Iterations || work > MaximumPbkdf2Iterations) return false;
            iterations = (int)work;
            return true;
        }
    }
}
