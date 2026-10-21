using System;
using System.Security.Cryptography;
#if NET48
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
#endif

namespace Vespertan.Cryptography
{
    public static partial class CryptoStrings
    {
        private static byte[] DerivePbkdf2Sha256(string password, byte[] salt, int iterations, int length)
        {
            // Use the same strict UTF-8 byte representation on both runtimes.
            var passwordBytes = Pbkdf2Utf8.GetBytes(password);
            try
            {
#if NET48
                // Framework imposes an eight-byte salt minimum not required by PBKDF2.
                // Preserve the existing low-level API and RFC vectors through Windows' native KDF.
                if (salt.Length < 8)
                    return DeriveShortSaltPbkdf2(passwordBytes, salt, iterations, length);
                using var kdf = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, HashAlgorithmName.SHA256);
                return kdf.GetBytes(length);
#else
                return Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA256, length);
#endif
            }
            finally
            {
#if NET48
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
#else
                CryptographicOperations.ZeroMemory(passwordBytes);
#endif
            }
        }

#if NET48
        private static byte[] DeriveShortSaltPbkdf2(byte[] password, byte[] salt, int iterations, int length)
        {
            const uint hmacFlag = 0x00000008;
            var status = BCryptOpenAlgorithmProvider(out var algorithm, "SHA256", null, hmacFlag);
            using (algorithm)
            {
                CheckPbkdf2Status(status);
                var result = new byte[length];
                status = BCryptDeriveKeyPBKDF2(algorithm, password, password.Length, salt, salt.Length,
                    (ulong)iterations, result, result.Length, 0);
                if (status < 0)
                {
                    Array.Clear(result, 0, result.Length);
                    CheckPbkdf2Status(status);
                }
                return result;
            }
        }

        private static void CheckPbkdf2Status(int status)
        {
            if (status < 0)
                throw new CryptographicException("Windows PBKDF2 failed with NTSTATUS 0x" + status.ToString("X8") + ".");
        }

        private sealed class Pbkdf2AlgorithmHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public Pbkdf2AlgorithmHandle() : base(true) { }
            protected override bool ReleaseHandle() => BCryptCloseAlgorithmProvider(handle, 0) >= 0;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int BCryptOpenAlgorithmProvider(out Pbkdf2AlgorithmHandle algorithm,
            string algorithmId, string implementation, uint flags);

        [DllImport("bcrypt.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int BCryptDeriveKeyPBKDF2(Pbkdf2AlgorithmHandle algorithm,
            [In] byte[] password, int passwordLength, [In] byte[] salt, int saltLength,
            ulong iterations, [Out] byte[] derivedKey, int derivedKeyLength, uint flags);

        [DllImport("bcrypt.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr algorithm, uint flags);
#endif
    }
}
