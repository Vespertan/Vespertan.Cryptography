using System;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Vespertan.Cryptography
{
    public static partial class CryptoStrings
    {

        #region Hash

        public static byte[] HashMd5(byte[] data)
        {
            using var hashAlg = MD5.Create();
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashMd5(string text)
        {
            return HashMd5(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] HashSha1(byte[] data)
        {
            using var hashAlg = SHA1.Create();
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashSha1(string text)
        {
            return HashSha1(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] HashSha256(byte[] data)
        {
            using var hashAlg = SHA256.Create();
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashSha256(string text)
        {
            return HashSha256(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] HashSha384(byte[] data)
        {
            using var hashAlg = SHA384.Create();
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashSha384(string text)
        {
            return HashSha384(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] HashSha512(byte[] data)
        {
            using var hashAlg = SHA512.Create();
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashSha512(string text)
        {
            return HashSha512(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] EncryptAes(string data, string password, ref byte[] salt)
        {
            return EncryptAes(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(password), ref salt);
        }

        public static byte[] EncryptAes(string data, byte[] password, ref byte[] salt)
        {
            return EncryptAes(Encoding.UTF8.GetBytes(data), password, ref salt);
        }

        public static byte[] EncryptAes(byte[] data, string password, ref byte[] salt)
        {
            return EncryptAes(data, Encoding.UTF8.GetBytes(password), ref salt);
        }

        public static byte[] EncryptAes(byte[] data, byte[] password, ref byte[] salt)
        {
            using var aesAlg = Aes.Create();

            var keyLen = aesAlg.KeySize / 8;
            var key = new byte[keyLen];
            Array.Copy(password, key, password.Length > keyLen ? keyLen : password.Length);
            aesAlg.Key = key;

            var ivLen = aesAlg.BlockSize / 8;
            var iv = new byte[ivLen];
            Array.Copy(salt, iv, salt.Length > ivLen ? ivLen : salt.Length);
            aesAlg.IV = iv;
            salt = iv;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using var swEncrypt = new BinaryWriter(csEncrypt);

            swEncrypt.Write(data, 0, data.Length);
            swEncrypt.Close();

            return msEncrypt.ToArray();
        }


        public static byte[] DecryptAes(byte[] data, string password, byte[] salt)
        {
            return DecryptAes(data, Encoding.UTF8.GetBytes(password), salt);
        }

        public static byte[] DecryptAes(byte[] data, byte[] password, byte[] salt)
        {
            using var aesAlg = Aes.Create();

            var keyLen = aesAlg.KeySize / 8;
            var key = new byte[keyLen];
            Array.Copy(password, key, password.Length > keyLen ? keyLen : password.Length);
            aesAlg.Key = key;

            var ivLen = aesAlg.BlockSize / 8;
            var iv = new byte[ivLen];
            Array.Copy(salt, iv, salt.Length > ivLen ? ivLen : salt.Length);
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var msDecrypt = new MemoryStream(data);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new BinaryReader(csDecrypt);
            using var msHelper = new MemoryStream();
            srDecrypt.BaseStream.CopyTo(msHelper);

            return msHelper.ToArray();
        }

        #endregion

        #region Strings

        public static string GetMd5CryptoString(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashMd5(data);
            return $"${CryptoType.Md5}${Convert.ToBase64String(hash)}";
        }

        public static string GetMd5SaltedCryptoString(string password, int saltLength)
        {
            var salt = GetRandomBytes(saltLength);
            return GetMd5SaltedCryptoString(password, salt);
        }

        public static string GetMd5SaltedCryptoString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            var hash = HashMd5(data);
            return $"${CryptoType.Md5Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        public static string GetNoneCryptoString(string password)
        {
            return $"${CryptoType.None}${password}";
        }

        public static string GetNoneCryptoString(byte[] data)
        {
            var dataAsBase64 = Convert.ToBase64String(data);
            return $"${CryptoType.NoneData}${dataAsBase64}";
        }

        public static string GetSha1CryptoString(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha1(data);
            return $"${CryptoType.Sha1}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha1SaltedCryptoString(string password, int saltLength)
        {
            var salt = GetRandomBytes(saltLength);
            return GetSha1SaltedCryptoString(password, salt);
        }

        public static string GetSha1SaltedCryptoString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            var hash = HashSha1(data);
            return $"${CryptoType.Sha1Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        public static string GetSha256CryptoString(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha256(data);
            return $"${CryptoType.Sha256}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha256SaltedCryptoString(string password, int saltLength)
        {
            var salt = GetRandomBytes(saltLength);
            return GetSha256SaltedCryptoString(password, salt);
        }

        public static string GetSha256SaltedCryptoString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            var hash = HashSha256(data);
            return $"${CryptoType.Sha256Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        public static string GetSha384CryptoString(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha384(data);
            return $"${CryptoType.Sha384}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha384SaltedCryptoString(string password, int saltLength)
        {
            var salt = GetRandomBytes(saltLength);
            return GetSha384SaltedCryptoString(password, salt);
        }

        public static string GetSha384SaltedCryptoString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            var hash = HashSha384(data);
            return $"${CryptoType.Sha384Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        public static string GetSha512CryptoString(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            byte[] hash = HashSha512(data);
            return $"${CryptoType.Sha512}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha512SaltedCryptoString(string password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetSha512SaltedCryptoString(password, salt);
        }

        public static string GetSha512SaltedCryptoString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            byte[] hash = HashSha512(data);
            return $"${CryptoType.Sha512Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        #region AES string

        public static string GetAesCryptoString(string data, string password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetAesCryptoString(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(password), salt);
        }

        public static string GetAesCryptoString(string data, string password, byte[] salt)
        {
            return GetAesCryptoString(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(password), salt);
        }

        public static string GetAesCryptoString(string data, byte[] password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetAesCryptoString(Encoding.UTF8.GetBytes(data), password, salt);
        }

        public static string GetAesCryptoString(string data, byte[] password, byte[] salt)
        {
            return GetAesCryptoString(Encoding.UTF8.GetBytes(data), password, salt);
        }

        public static string GetAesCryptoString(byte[] data, string password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetAesCryptoString(data, Encoding.UTF8.GetBytes(password), salt);
        }

        public static string GetAesCryptoString(byte[] data, string password, byte[] salt)
        {
            return GetAesCryptoString(data, Encoding.UTF8.GetBytes(password), salt);
        }

        public static string GetAesCryptoString(byte[] data, byte[] password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetAesCryptoString(data, password, salt);
        }

        public static string GetAesCryptoString(byte[] data, byte[] password, byte[] salt)
        {
            var encryptedData = EncryptAes(data, password, ref salt);
            return $"${CryptoType.Aes}${Convert.ToBase64String(encryptedData)}${Convert.ToBase64String(salt)}";
        }

        public static string DecryptAesText(string cryptoString, string password)
        {
            if (UsesAuthenticatedAesFormat(cryptoString))
                return DecryptAuthenticatedAesText(cryptoString, password);
            return DecryptAesText(cryptoString, Encoding.UTF8.GetBytes(password));
        }

        public static string DecryptAesText(string cryptoString, byte[] password)
        {
            if (cryptoString == null)
            {
                return null;
            }

            return Encoding.UTF8.GetString(DecryptAesData(cryptoString, password));
        }

        public static byte[] DecryptAesData(string cryptoString, string password)
        {
            if (UsesAuthenticatedAesFormat(cryptoString))
                return DecryptAuthenticatedAesData(cryptoString, password);
            return DecryptAesData(cryptoString, Encoding.UTF8.GetBytes(password));
        }

        public static byte[] DecryptAesData(string cryptoString, byte[] password)
        {
            if (UsesAuthenticatedAesFormat(cryptoString))
                return DecryptAuthenticatedAesFromUtf8(cryptoString, password);
            if (cryptoString == null)
            {
                return null;
            }

            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Aes)
            {
                throw new InvalidOperationException();
            }
            return DecryptAes(parts.Hash, password, parts.DataAsByteArray);
        }

        public static string DecryptText(string cryptoString, byte[] password)
        {
            return DecryptText(cryptoString, password, null);
        }

        public static string DecryptText(string cryptoString, string password)
        {
            return DecryptText(cryptoString, password, null);
        }

        public static string DecryptText(string cryptoString, string password, RSA privateKey)
        {
            if (UsesAuthenticatedAesFormat(cryptoString))
                return DecryptAuthenticatedAesText(cryptoString, password);
            return DecryptText(cryptoString, password == null ? null : Encoding.UTF8.GetBytes(password), privateKey);
        }

        public static string DecryptText(string cryptoString, byte[] password, RSA privateKey)
        {
            if (cryptoString == null)
            {
                return null;
            }
            var data = DecryptData(cryptoString, password, privateKey);
            return Encoding.UTF8.GetString(data);
        }
        
        public static byte[] DecryptData(string cryptoString, RSA privateKey)
        {
            return DecryptData(cryptoString, (byte[])null, privateKey);
        }

        public static byte[] DecryptData(string cryptoString, string password, RSA privateKey)
        {
            if (UsesAuthenticatedAesFormat(cryptoString))
                return DecryptAuthenticatedAesData(cryptoString, password);
            var passwordAsBytes = password == null ? null : Encoding.UTF8.GetBytes(password);
            return DecryptData(cryptoString, passwordAsBytes, privateKey);
        }
        public static byte[] DecryptData(string cryptoString, string password)
        {
            return DecryptData(cryptoString, password, null);
        }

        public static byte[] DecryptData(string cryptoString, byte[] password)
        {
            return DecryptData(cryptoString, password, null);
        }
        /// <summary>Decrypts encrypted records or extracts hash data.</summary>
        /// <remarks>Sign records require a trusted RSA verification key in privateKey and are verified before returning data.</remarks>
        public static byte[] DecryptData(string cryptoString, byte[] password, RSA privateKey)
        {
            if (UsesAuthenticatedAesFormat(cryptoString))
                return DecryptAuthenticatedAesFromUtf8(cryptoString, password);
            if (cryptoString == null)
            {
                return null;
            }

            var parts = new HashParts(cryptoString);
            switch (parts.Type)
            {
                case CryptoType.None:
                case CryptoType.Sha1:
                case CryptoType.Md5:
                case CryptoType.Sha256:
                case CryptoType.Sha384:
                case CryptoType.Sha512:
                case CryptoType.Sha1Salt:
                case CryptoType.Md5Salt:
                case CryptoType.Sha256Salt:
                case CryptoType.Sha384Salt:
                case CryptoType.Sha512Salt:
                case CryptoType.Pbkdf2:
                    return parts.Hash;
                case CryptoType.Sign:
                    return GetSignData(cryptoString, privateKey);
                case CryptoType.Aes:
                    return DecryptAes(parts.Hash, password, parts.DataAsByteArray);
                case CryptoType.Cert:
                    return DecryptCertData(cryptoString, privateKey);
                default:
                    throw new InvalidOperationException();
            }
        }

        #endregion

        #region Certificate

        private static byte[] EncryptCert(byte[] data, RSA publicKey)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            byte[] encryptedKey = publicKey.Encrypt(data, RSAEncryptionPadding.OaepSHA1);
            return encryptedKey;
        }

        private static byte[] DecryptCert(byte[] data, RSA privateKey)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            byte[] decryptedValue = privateKey.Decrypt(data, RSAEncryptionPadding.OaepSHA1);
            return decryptedValue;
        }

        public static string GetCertCryptoString(string text, X509Certificate2 certificate2)
        {
            using var rsa = GetCertificatePublicKey(certificate2);
            return GetCertCryptoString(Encoding.UTF8.GetBytes(text), rsa, certificate2.Thumbprint);
        }

        public static string GetCertCryptoString(string text, RSA publicKey, string thumbprint = null)
        {
            return GetCertCryptoString(Encoding.UTF8.GetBytes(text), publicKey, thumbprint);
        }

        public static string GetCertCryptoString(byte[] data, RSA publicKey, string thumbprint = null)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            var saltPart = Convert.ToBase64String(salt);
            var password = GetRandomBytes(20);
            var encryptedData = EncryptAes(data, password, ref salt);
            var encryptedDataPart = Convert.ToBase64String(encryptedData);
            var passwordEncrypted = EncryptCert(password, publicKey);
            var passwordPart = Convert.ToBase64String(passwordEncrypted);

            return $"${CryptoType.Cert}${encryptedDataPart}${saltPart};{passwordPart};{thumbprint}";
        }

        public static byte[] DecryptCertData(byte[] hash, RSA privateKey, byte[] password, byte[] salt)
        {
            byte[] passwordDecrypted = DecryptCert(password, privateKey);
            try
            {
                return DecryptAes(hash, passwordDecrypted, salt);
            }
            finally
            {
                Array.Clear(passwordDecrypted, 0, passwordDecrypted.Length);
            }
        }

        public static byte[] DecryptCertData(string cryptoString, RSA privateKey)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Cert)
            {
                throw new InvalidOperationException();
            }
            var (salt, encyptedPassword, _) = GetCertDataParts(parts.Data);
            return DecryptCertData(parts.Hash, privateKey, encyptedPassword, salt);
        }

        public static string DecryptCertText(string cryptoString, RSA privateKey)
        {
            return Encoding.UTF8.GetString(DecryptCertData(cryptoString, privateKey));
        }

        private static (byte[] salt, byte[] encyptedPassword, string thumbprint) GetCertDataParts(string data)
        {
            var dataParts = data?.Split(new[] { ';' }, 3);
            if (dataParts == null || dataParts.Length != 3)
                throw new FormatException("Invalid certificate metadata.");
            var salt = Convert.FromBase64String(dataParts[0]);
            var password = Convert.FromBase64String(dataParts[1]);
            var thumbprint = dataParts[2];
            return (salt, password, thumbprint);
        }

        public static byte[] DecryptCertData(string cryptoString, X509Certificate2 x509Certificate2)
        {
            using var privateKey = GetCertificatePrivateKey(x509Certificate2);
            return DecryptCertData(cryptoString, privateKey);
        }

        public static string DecryptCertText(string cryptoString, X509Certificate2 x509Certificate2)
        {
            return Encoding.UTF8.GetString(DecryptCertData(cryptoString, x509Certificate2));
        }

        private static RSA GetCertificatePublicKey(X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            return certificate.GetRSAPublicKey()
                ?? throw new CryptographicException("An RSA public key is required.");
        }

        private static RSA GetCertificatePrivateKey(X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            return certificate.GetRSAPrivateKey()
                ?? throw new CryptographicException("An RSA private key is required.");
        }

        #endregion

        #region Signature

        private static byte[] Sign(byte[] data, RSA privateKey)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            var signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return signature;
        }

        private static bool VerifySign(byte[] data, RSA publicKey, byte[] signature)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            var ok = publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return ok;
        }

        public static string GetSignCryptoString(string text, X509Certificate2 certificate2)
        {
            using var privateKey = GetCertificatePrivateKey(certificate2);
            return GetSignCryptoString(Encoding.UTF8.GetBytes(text), privateKey, certificate2.Thumbprint);
        }

        public static string GetSignCryptoString(string text, RSA privateKey, string thumbprint = null)
        {
            return GetSignCryptoString(Encoding.UTF8.GetBytes(text), privateKey, thumbprint);
        }

        public static string GetSignCryptoString(byte[] data, RSA privateKey, string thumbprint = null)
        {
            var dataPart = Convert.ToBase64String(data);
            var sign = Sign(data, privateKey);
            var signPart = Convert.ToBase64String(sign);

            return $"${CryptoType.Sign}${dataPart}${signPart};{thumbprint}";
        }

        public static bool VerifySign(string cryptoString, RSA publicKey)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Sign)
            {
                throw new InvalidOperationException();
            }
            var (sign, thumbprint) = GetSignDataParts(parts.Data);
            return VerifySign(parts.Hash, publicKey, sign);
        }

        private static (byte[] sign, string thumbprint) GetSignDataParts(string data)
        {
            var dataParts = data?.Split(new[] { ';' }, 2);
            if (dataParts == null || dataParts.Length != 2)
                throw new FormatException("Invalid signature metadata.");
            var sign = Convert.FromBase64String(dataParts[0]);
            var thumbprint = dataParts[1];
            return (sign, thumbprint);
        }

        public static bool VerifySign(string cryptoString, X509Certificate2 x509Certificate2)
        {
            using var publicKey = GetCertificatePublicKey(x509Certificate2);
            return VerifySign(cryptoString, publicKey);
        }

        public static string GetSignText(string cryptoString, X509Certificate2 x509Certificate2)
        {
            return Encoding.UTF8.GetString(GetSignData(cryptoString, x509Certificate2));
        }

        public static byte[] GetSignData(string cryptoString, X509Certificate2 x509Certificate2)
        {
            using var publicKey = GetCertificatePublicKey(x509Certificate2);
            return GetSignData(cryptoString, publicKey);
        }

        /// <summary>Returns signed data only after verifying it with the caller's trusted RSA public key.</summary>
        public static byte[] GetSignData(string cryptoString, RSA publicKey)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Sign)
            {
                throw new InvalidOperationException();
            }
            var (sign, thumbprint) = GetSignDataParts(parts.Data);
            var ok = VerifySign(parts.Hash, publicKey, sign);
            if (ok)
            {
                return parts.Hash;
            }
            else
            {
                throw new InvalidOperationException("Signature verification failed");
            }
        }

        #endregion


        #endregion

        public static HashParts GetHashParts(string cryptoString)
        {
            return new HashParts(cryptoString);
        }

        public static bool IsValidCryptoString(string hash)
        {
            return HashParts.IsValidHash(hash);
        }

        public static byte[] GetRandomBytes(int count)
        {
            byte[] randomData = new byte[count];
            using var rngCsp = RandomNumberGenerator.Create();
            rngCsp.GetBytes(randomData);
            return randomData;
        }

        public static bool ValidatePasswordString(string password, string cryptoString)
        {
            if (cryptoString != null && cryptoString.StartsWith(Pbkdf2Prefix, StringComparison.OrdinalIgnoreCase))
            {
                return VerifyPbkdf2CryptoString(password, cryptoString);
            }

            var hashParts = new HashParts(cryptoString);
            var passwordData = Encoding.UTF8.GetBytes(password);
            return hashParts.Type switch
            {
                CryptoType.None => ArraysEquals(hashParts.Hash, passwordData),
                CryptoType.NoneData => ArraysEquals(hashParts.Hash, passwordData),
                CryptoType.Md5 => ArraysEquals(hashParts.Hash, HashMd5(passwordData)),
                CryptoType.Md5Salt => ArraysEquals(hashParts.Hash, HashMd5(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                CryptoType.Sha1 => ArraysEquals(hashParts.Hash, HashSha1(passwordData)),
                CryptoType.Sha1Salt => ArraysEquals(hashParts.Hash, HashSha1(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                CryptoType.Sha256 => ArraysEquals(hashParts.Hash, HashSha256(passwordData)),
                CryptoType.Sha256Salt => ArraysEquals(hashParts.Hash, HashSha256(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                CryptoType.Sha384 => ArraysEquals(hashParts.Hash, HashSha384(passwordData)),
                CryptoType.Sha384Salt => ArraysEquals(hashParts.Hash, HashSha384(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                CryptoType.Sha512 => ArraysEquals(hashParts.Hash, HashSha512(passwordData)),
                CryptoType.Sha512Salt => ArraysEquals(hashParts.Hash, HashSha512(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                _ => throw new NotSupportedException(),
            };
        }

        // .NET Framework has no CryptographicOperations.FixedTimeEquals.
#if NET48
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
#endif
        internal static bool ArraysEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null)
            {
                return false;
            }
            else if (a.Length != b.Length)
            {
                return false;
            }
#if NET48
            var difference = 0;
            for (int i = 0; i < a.Length; i++)
            {
                difference |= a[i] ^ b[i];
            }
            return difference == 0;
#else
            return CryptographicOperations.FixedTimeEquals(a, b);
#endif
        }

        internal static byte[] ConcateArray(byte[] a, byte[] b)
        {
            var union = new byte[a.Length + b.Length];
            Array.Copy(a, union, a.Length);
            Array.Copy(b, 0, union, a.Length, b.Length);
            return union;
        }
    }
}
