using System;
using System.Globalization;
using System.Text;

namespace Vespertan.Cryptography
{
    public static partial class CryptoStrings
    {
        public const int DefaultPbkdf2Iterations = 600_000;
        public const int MaximumPbkdf2Iterations = 2_000_000;
        public const int Pbkdf2SaltLength = 16;
        public const int Pbkdf2HashLength = 32;
        internal const string Pbkdf2Prefix = "$Pbkdf2$";
        private const int MaximumPbkdf2SaltLength = 64;
        private const int MaximumPbkdf2StringLength = 160;
        private static readonly UTF8Encoding Pbkdf2Utf8 = new UTF8Encoding(false, true);

        /// <summary>Derives 32 bytes using PBKDF2-HMAC-SHA256 and a UTF-8 password.</summary>
        /// <remarks>
        /// Low-level interoperability API: accepts 1..2,000,000 iterations and 1..64 salt bytes.
        /// For password storage use GetPbkdf2CryptoString, which enforces stronger parameters.
        /// The caller owns the returned key and should clear it after use.
        /// </remarks>
        public static byte[] HashPbkdf2(string password, byte[] salt, int iterations = DefaultPbkdf2Iterations)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (salt.Length < 1 || salt.Length > MaximumPbkdf2SaltLength)
                throw new ArgumentOutOfRangeException(nameof(salt));
            CheckPbkdf2Iterations(iterations, 1);
            // Reject unpaired surrogates rather than mapping distinct passwords to U+FFFD.
            Pbkdf2Utf8.GetByteCount(password);

            return DerivePbkdf2Sha256(password, salt, iterations, Pbkdf2HashLength);
        }

        /// <summary>Creates a password verifier with a fresh cryptographically random 16-byte salt.</summary>
        public static string GetPbkdf2CryptoString(string password, int iterations = DefaultPbkdf2Iterations)
        {
            return GetPbkdf2CryptoString(password, GetRandomBytes(Pbkdf2SaltLength), iterations);
        }

        /// <summary>Creates a password verifier with an explicit 16..64-byte salt.</summary>
        /// <remarks>Use a unique random salt per password. Iterations must be 600,000..2,000,000.</remarks>
        public static string GetPbkdf2CryptoString(string password, byte[] salt, int iterations = DefaultPbkdf2Iterations)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (salt.Length < Pbkdf2SaltLength || salt.Length > MaximumPbkdf2SaltLength)
                throw new ArgumentOutOfRangeException(nameof(salt));
            CheckPbkdf2Iterations(iterations, DefaultPbkdf2Iterations);

            // Keep the serialized salt identical to the salt used for derivation.
            var saltCopy = (byte[])salt.Clone();
            var hash = HashPbkdf2(password, saltCopy, iterations);
            try
            {
                return Pbkdf2Prefix + Convert.ToBase64String(hash) + "$1;SHA256;"
                    + iterations.ToString(CultureInfo.InvariantCulture) + ";" + Convert.ToBase64String(saltCopy);
            }
            finally
            {
                Array.Clear(hash, 0, hash.Length);
            }
        }

        /// <summary>Verifies a PBKDF2 password record. Null or malformed input returns false.</summary>
        /// <remarks>
        /// Reads historical iteration counts down to 1, but rejects counts above 2,000,000 before derivation.
        /// Applications must rate-limit authentication requests and upgrade weak records after successful login.
        /// </remarks>
        public static bool VerifyPbkdf2CryptoString(string password, string cryptoString)
        {
            if (password == null || !TryReadPbkdf2(cryptoString, out var expected, out var salt, out var iterations))
                return false;

            byte[] actual = null;
            try
            {
                actual = HashPbkdf2(password, salt, iterations);
                return ArraysEquals(actual, expected);
            }
            catch (EncoderFallbackException)
            {
                return false;
            }
            finally
            {
                if (actual != null) Array.Clear(actual, 0, actual.Length);
            }
        }

        private static void CheckPbkdf2Iterations(int iterations, int minimum)
        {
            if (iterations < minimum || iterations > MaximumPbkdf2Iterations)
                throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        /// <summary>Checks whether a record needs replacement with the requested PBKDF2 work factor.</summary>
        /// <remarks>This is not password verification. Only replace a record after successful authentication.</remarks>
        public static bool NeedsPbkdf2Rehash(string cryptoString, int iterations = DefaultPbkdf2Iterations)
        {
            CheckPbkdf2Iterations(iterations, DefaultPbkdf2Iterations);
            return !TryReadPbkdf2(cryptoString, out _, out _, out var storedIterations)
                || storedIterations < iterations;
        }

        // Validate all untrusted metadata and allocation/work limits before running the KDF.
        internal static bool TryReadPbkdf2(string value, out byte[] hash, out byte[] salt, out int iterations)
        {
            hash = null;
            salt = null;
            iterations = 0;
            if (value == null || value.Length > MaximumPbkdf2StringLength
                || !value.StartsWith(Pbkdf2Prefix, StringComparison.OrdinalIgnoreCase))
                return false;

            var parts = value.Split('$');
            if (parts.Length != 4 || parts[2].Length != 44) return false;
            var metadata = parts[3].Split(';');
            if (metadata.Length != 4 || metadata[0] != "1" || metadata[1] != "SHA256"
                || !int.TryParse(metadata[2], NumberStyles.None, CultureInfo.InvariantCulture, out iterations)
                || iterations < 1 || iterations > MaximumPbkdf2Iterations
                || metadata[2] != iterations.ToString(CultureInfo.InvariantCulture))
                return false;

            try
            {
                hash = Convert.FromBase64String(parts[2]);
                salt = Convert.FromBase64String(metadata[3]);
                return hash.Length == Pbkdf2HashLength
                    && salt.Length >= Pbkdf2SaltLength && salt.Length <= MaximumPbkdf2SaltLength
                    && Convert.ToBase64String(hash) == parts[2]
                    && Convert.ToBase64String(salt) == metadata[3];
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }
}
