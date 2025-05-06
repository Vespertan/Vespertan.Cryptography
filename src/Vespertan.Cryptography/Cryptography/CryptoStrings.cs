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

        public static string GetMd5String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashMd5(data);
            return $"${PasswordType.Md5}${Convert.ToBase64String(hash)}";
        }

        public static string GetMd5SaltedString(string password, int saltLength)
        {
            var salt = GetRandomBytes(saltLength);
            return GetMd5SaltedString(password, salt);
        }

        public static string GetMd5SaltedString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            var hash = HashMd5(data);
            return $"${PasswordType.Md5Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        public static string GetNoneString(string password)
        {
            return $"${PasswordType.None}${password}";
        }

        public static string GetSha1String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha1(data);
            return $"${PasswordType.Sha1}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha1SaltedString(string password, int saltLength)
        {
            var salt = GetRandomBytes(saltLength);
            return GetSha1SaltedString(password, salt);
        }

        public static string GetSha1SaltedString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            var hash = HashSha1(data);
            return $"${PasswordType.Sha1Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        public static string GetSha256String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha256(data);
            return $"${PasswordType.Sha256}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha256SaltedString(string password, int saltLength)
        {
            var salt = GetRandomBytes(saltLength);
            return GetSha256SaltedString(password, salt);
        }

        public static string GetSha256SaltedString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            var hash = HashSha256(data);
            return $"${PasswordType.Sha256Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        public static string GetSha384String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha384(data);
            return $"${PasswordType.Sha384}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha384SaltedString(string password, int saltLength)
        {
            var salt = GetRandomBytes(saltLength);
            return GetSha384SaltedString(password, salt);
        }

        public static string GetSha384SaltedString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            var hash = HashSha384(data);
            return $"${PasswordType.Sha384Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        public static string GetSha512String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            byte[] hash = HashSha512(data);
            return $"${PasswordType.Sha512}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha512SaltedString(string password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetSha512SaltedString(password, salt);
        }

        public static string GetSha512SaltedString(string password, byte[] salt)
        {
            var data = ConcateArray(Encoding.UTF8.GetBytes(password), salt);
            byte[] hash = HashSha512(data);
            return $"${PasswordType.Sha512Salt}${Convert.ToBase64String(hash)}${Convert.ToBase64String(salt)}";
        }

        #region AES string

        public static string GetAesString(string data, string password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetAesString(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(password), salt);
        }

        public static string GetAesString(string data, string password, byte[] salt)
        {
            return GetAesString(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(password), salt);
        }

        public static string GetAesString(string data, byte[] password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetAesString(Encoding.UTF8.GetBytes(data), password, salt);
        }

        public static string GetAesString(string data, byte[] password, byte[] salt)
        {
            return GetAesString(Encoding.UTF8.GetBytes(data), password, salt);
        }

        public static string GetAesString(byte[] data, string password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetAesString(data, Encoding.UTF8.GetBytes(password), salt);
        }

        public static string GetAesString(byte[] data, string password, byte[] salt)
        {
            return GetAesString(data, Encoding.UTF8.GetBytes(password), salt);
        }

        public static string GetAesString(byte[] data, byte[] password)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            return GetAesString(data, password, salt);
        }

        public static string GetAesString(byte[] data, byte[] password, byte[] salt)
        {
            var encryptedData = EncryptAes(data, password, ref salt);
            return $"${PasswordType.Aes}${Convert.ToBase64String(encryptedData)}${Convert.ToBase64String(salt)}";
        }

        public static string DecryptAesText(string cryptoString, string password)
        {
            return DecryptAesText(cryptoString, Encoding.UTF8.GetBytes(password));
        }

        public static string DecryptAesText(string cryptoString, byte[] password)
        {
            return Encoding.UTF8.GetString(DecryptAesData(cryptoString, password));
        }

        public static byte[] DecryptAesData(string cryptoString, string password)
        {
            return DecryptAesData(cryptoString, Encoding.UTF8.GetBytes(password));
        }

        public static byte[] DecryptAesData(string cryptoString, byte[] password)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != PasswordType.Aes)
            {
                throw new InvalidOperationException();
            }
            return DecryptAes(parts.Hash, password, parts.DataAsByteArray);
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

        public static string GetCertString(string text, X509Certificate2 certificate2)
        {
                using var rsa = certificate2.GetRSAPublicKey();
                return GetCertString(Encoding.UTF8.GetBytes(text), rsa, certificate2.Thumbprint);
        }

        public static string GetCertString(string text, RSA publicKey, string thumbprint = null)
        {
            return GetCertString(Encoding.UTF8.GetBytes(text), publicKey, thumbprint);
        }

        public static string GetCertString(byte[] data, RSA publicKey, string thumbprint = null)
        {
            var salt = GetRandomBytes(Aes.Create().KeySize / 8);
            var saltPart = Convert.ToBase64String(salt);
            var password = GetRandomBytes(20);
            var encryptedData = EncryptAes(data, password, ref salt);
            var encryptedDataPart = Convert.ToBase64String(encryptedData);
            var passwordEncrypted = EncryptCert(password, publicKey);
            var passwordPart = Convert.ToBase64String(passwordEncrypted);

            return $"${PasswordType.Cert}${encryptedDataPart}${saltPart};{passwordPart};{thumbprint}";
        }

        public static byte[] DecryptCertData(byte[] hash, RSA privateKey, byte[] password, byte[] salt)
        {
            byte[] passwordDecrypted = DecryptCert(password, privateKey);
            return DecryptAes(hash, passwordDecrypted, salt);
        }

        public static byte[] DecryptCertData(string cryptoString, RSA privateKey)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != PasswordType.Cert)
            {
                throw new InvalidOperationException();
            }
            var (salt, encyptedPassword, _) = GetCertDataParts(parts.Data);
            return DecryptCertData(parts.Hash, privateKey, encyptedPassword, salt);
        }

        public static string DecryptCertText(string cryptoString, RSA privateKey)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != PasswordType.Cert)
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
            if (parts.Type != PasswordType.Cert)
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
            if (parts.Type != PasswordType.Cert)
            {
                throw new InvalidOperationException();
            }
            var (salt, encyptedPassword, _) = GetCertDataParts(parts.Data);
            using var privateKey = x509Certificate2.GetRSAPrivateKey();
            var data = DecryptCertData(parts.Hash, privateKey, encyptedPassword, salt);
            return Encoding.UTF8.GetString(data);
        }

        #endregion

        #endregion

        public static HashParts GetHashParts(string cryptoString)
        {
            return new HashParts(cryptoString);
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
                PasswordType.None => ArraysEquals(hashParts.Hash, passwordData),
                PasswordType.Md5 => ArraysEquals(hashParts.Hash, HashMd5(passwordData)),
                PasswordType.Md5Salt => ArraysEquals(hashParts.Hash, HashMd5(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                PasswordType.Sha1 => ArraysEquals(hashParts.Hash, HashSha1(passwordData)),
                PasswordType.Sha1Salt => ArraysEquals(hashParts.Hash, HashSha1(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                PasswordType.Sha256 => ArraysEquals(hashParts.Hash, HashSha256(passwordData)),
                PasswordType.Sha256Salt => ArraysEquals(hashParts.Hash, HashSha256(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                PasswordType.Sha384 => ArraysEquals(hashParts.Hash, HashSha384(passwordData)),
                PasswordType.Sha384Salt => ArraysEquals(hashParts.Hash, HashSha384(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                PasswordType.Sha512 => ArraysEquals(hashParts.Hash, HashSha512(passwordData)),
                PasswordType.Sha512Salt => ArraysEquals(hashParts.Hash, HashSha512(ConcateArray(passwordData, hashParts.DataAsByteArray))),
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
