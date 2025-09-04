using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Vespertan.Cryptography
{
    public static class CryptoStrings
    {

        #region Hash

        public static byte[] HashMd5(byte[] data)
        {
            using var hashAlg = HashAlgorithm.Create(HashAlgorithmName.MD5.Name);
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashMd5(string text)
        {
            return HashMd5(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] HashSha1(byte[] data)
        {
            using var hashAlg = HashAlgorithm.Create(HashAlgorithmName.SHA1.Name);
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashSha1(string text)
        {
            return HashSha1(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] HashSha256(byte[] data)
        {
            using var hashAlg = HashAlgorithm.Create(HashAlgorithmName.SHA256.Name);
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashSha256(string text)
        {
            return HashSha256(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] HashSha384(byte[] data)
        {
            using var hashAlg = HashAlgorithm.Create(HashAlgorithmName.SHA384.Name);
            return hashAlg.ComputeHash(data);
        }

        public static byte[] HashSha384(string text)
        {
            return HashSha384(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] HashSha512(byte[] data)
        {
            using var hashAlg = HashAlgorithm.Create(HashAlgorithmName.SHA512.Name);
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
            return DecryptAesData(cryptoString, Encoding.UTF8.GetBytes(password));
        }

        public static byte[] DecryptAesData(string cryptoString, byte[] password)
        {
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
            return DecryptText(cryptoString, Encoding.UTF8.GetBytes(password), null);
        }

        public static string DecryptText(string cryptoString, string password, RSA privateKey)
        {
            return DecryptText(cryptoString, Encoding.UTF8.GetBytes(password), privateKey);
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
            var passwordAsBytes = password == null ? null : Encoding.UTF8.GetBytes(password);
            return DecryptData(cryptoString, passwordAsBytes, privateKey);
        }
        public static byte[] DecryptData(string cryptoString, string password)
        {
            var passwordAsBytes = password == null ? null : Encoding.UTF8.GetBytes(password);
            return DecryptData(cryptoString, passwordAsBytes, null);
        }

        public static byte[] DecryptData(string cryptoString, byte[] password)
        {
            return DecryptData(cryptoString, password, null);
        }
        public static byte[] DecryptData(string cryptoString, byte[] password, RSA privateKey)
        {
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
                case CryptoType.Sign:
                    return parts.Hash;
                case CryptoType.Aes:
                    return DecryptAes(parts.Hash, password, parts.DataAsByteArray);
                case CryptoType.Cert:
                    return DecryptCert(parts.Hash, privateKey);
                default:
                    throw new InvalidOperationException();
            }
        }

        #endregion

        #region Certificate

        private static byte[] EncryptCert(byte[] data, RSA publicKey)
        {
            byte[] encryptedKey = publicKey.Encrypt(data, RSAEncryptionPadding.OaepSHA1);
            return encryptedKey;
        }

        private static byte[] DecryptCert(byte[] data, RSA privateKey)
        {
            byte[] decryptedValue = privateKey.Decrypt(data, RSAEncryptionPadding.OaepSHA1);
            return decryptedValue;
        }

        public static string GetCertCryptoString(string text, X509Certificate2 certificate2)
        {
            using var rsa = certificate2.GetRSAPublicKey();
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
            return DecryptAes(hash, passwordDecrypted, salt);
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
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Cert)
            {
                throw new InvalidOperationException();
            }

            var (salt, encyptedPassword, _) = GetCertDataParts(parts.Data);
            var data = DecryptCertData(parts.Hash, privateKey, encyptedPassword, salt);

            return Encoding.UTF8.GetString(data);
        }

        private static (byte[] salt, byte[] encyptedPassword, string thumbprint) GetCertDataParts(string data)
        {
            var dataParts = data.Split(';');
            var salt = Convert.FromBase64String(dataParts[0]);
            var password = Convert.FromBase64String(dataParts[1]);
            var thumbprint = dataParts[2];
            return (salt, password, thumbprint);
        }

        public static byte[] DecryptCertData(string cryptoString, X509Certificate2 x509Certificate2)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Cert)
            {
                throw new InvalidOperationException();
            }
            var (salt, encyptedPassword, _) = GetCertDataParts(parts.Data);
            using var privateKey = x509Certificate2.GetRSAPrivateKey();
            return DecryptCertData(parts.Hash, privateKey, encyptedPassword, salt);
        }

        public static string DecryptCertText(string cryptoString, X509Certificate2 x509Certificate2)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Cert)
            {
                throw new InvalidOperationException();
            }
            var (salt, encyptedPassword, _) = GetCertDataParts(parts.Data);
            using var privateKey = x509Certificate2.GetRSAPrivateKey();
            var data = DecryptCertData(parts.Hash, privateKey, encyptedPassword, salt);
            return Encoding.UTF8.GetString(data);
        }

        #endregion

        #region Signature

        private static byte[] Sign(byte[] data, RSA privateKey)
        {
            var signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return signature;
        }

        private static bool VerifySign(byte[] data, RSA publicKey, byte[] signature)
        {
            var ok = publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return ok;
        }

        public static string GetSignCryptoString(string text, X509Certificate2 certificate2)
        {
            using var privateKey = certificate2.GetRSAPrivateKey();
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
            var dataParts = data.Split(';');
            var sign = Convert.FromBase64String(dataParts[0]);
            var thumbprint = dataParts[1];
            return (sign, thumbprint);
        }

        public static bool VerifySign(string cryptoString, X509Certificate2 x509Certificate2)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Cert)
            {
                throw new InvalidOperationException();
            }
            var (sign, thumbprint) = GetSignDataParts(parts.Data);
            using var publicKey = x509Certificate2.GetRSAPublicKey();
            return VerifySign(parts.Hash, publicKey, sign);
        }

        public static string GetSignText(string cryptoString, X509Certificate2 x509Certificate2)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Sign)
            {
                throw new InvalidOperationException();
            }
            var (sign, thumbprint) = GetSignDataParts(parts.Data);
            using var publicKey = x509Certificate2.GetRSAPublicKey();
            var ok = VerifySign(parts.Hash, publicKey, sign);
            if (ok)
            {
                return Encoding.UTF8.GetString(parts.Hash);
            }
            else
            {
                throw new InvalidOperationException("Signature verification failed");
            }
        }

        public static byte[] GetSignData(string cryptoString, X509Certificate2 x509Certificate2)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != CryptoType.Sign)
            {
                throw new InvalidOperationException();
            }
            var (sign, thumbprint) = GetSignDataParts(parts.Data);
            using var privateKey = x509Certificate2.GetRSAPrivateKey();
            var ok = VerifySign(parts.Hash, privateKey, sign);
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
            using var rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(randomData);
            return randomData;
        }

        public static bool ValidatePasswordString(string password, string cryptoString)
        {
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
            else
            {
                for (int i = 0; i < a.Length; i++)
                {
                    if (a[i] != b[i])
                    {
                        return false;
                    }
                }
            }
            return true;
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
