using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Vespertan.Cryptography
{
    public static class CryptoStrings
    {
        public const string AlgMd5 = "md5";
        public const string AlgMd5Salt = "md5salt";
        private const string AlgNone = "none";
        private const string AlgSha1 = "sha1";
        private const string AlgSha1Salt = "sha1salt";
        private const string AlgSha256 = "sha256";
        private const string AlgSha256Salt = "sha256salt";
        private const string AlgSha384 = "sha384";
        private const string AlgSha384Salt = "sha384salt";
        private const string AlgSha512 = "sha512";
        private const string AlgSha512Salt = "sha512salt";
        private const string AlgAes = "aes";

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
            return $"${AlgMd5}${Convert.ToBase64String(hash)}";
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
            return $"${AlgMd5Salt}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }

        public static string GetNoneString(string password)
        {
            return $"${AlgNone}${password}";
        }

        public static string GetSha1String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha1(data);
            return $"${AlgSha1}${Convert.ToBase64String(hash)}";
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
            return $"${AlgSha1Salt}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha256String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha256(data);
            return $"${AlgSha256}${Convert.ToBase64String(hash)}";
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
            return $"${AlgSha256Salt}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha384String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            var hash = HashSha384(data);
            return $"${AlgSha384}${Convert.ToBase64String(hash)}";
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
            return $"${AlgSha384Salt}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }

        public static string GetSha512String(string password)
        {
            var data = Encoding.UTF8.GetBytes(password);
            byte[] hash = HashSha512(data);
            return $"${AlgSha512}${Convert.ToBase64String(hash)}";
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
            return $"${AlgSha512Salt}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
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
            return $"${AlgAes}${Convert.ToBase64String(salt)}${Convert.ToBase64String(encryptedData)}";
        }

        public static string GetDecryptedAesText(string cryptoString, string password)
        {
            return GetDecryptedAesText(cryptoString, Encoding.UTF8.GetBytes(password));
        }

        public static string GetDecryptedAesText(string cryptoString, byte[] password)
        {
            return Encoding.UTF8.GetString(GetDecryptedAesData(cryptoString, password));
        }

        public static byte[] GetDecryptedAesData(string cryptoString, string password)
        {
            return GetDecryptedAesData(cryptoString, Encoding.UTF8.GetBytes(password));
        }

        public static byte[] GetDecryptedAesData(string cryptoString, byte[] password)
        {
            var parts = new HashParts(cryptoString);
            if (parts.Type != AlgAes)
            {
                throw new InvalidOperationException();
            }
            return DecryptAes(parts.HashAsByteArray, password, parts.DataAsByteArray);
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
                AlgNone => ArraysEquals(hashParts.HashAsByteArray, passwordData),
                AlgMd5 => ArraysEquals(hashParts.HashAsByteArray, HashMd5(passwordData)),
                AlgMd5Salt => ArraysEquals(hashParts.HashAsByteArray, HashMd5(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                AlgSha1 => ArraysEquals(hashParts.HashAsByteArray, HashSha1(passwordData)),
                AlgSha1Salt => ArraysEquals(hashParts.HashAsByteArray, HashSha1(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                AlgSha256 => ArraysEquals(hashParts.HashAsByteArray, HashSha256(passwordData)),
                AlgSha256Salt => ArraysEquals(hashParts.HashAsByteArray, HashSha256(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                AlgSha384 => ArraysEquals(hashParts.HashAsByteArray, HashSha384(passwordData)),
                AlgSha384Salt => ArraysEquals(hashParts.HashAsByteArray, HashSha384(ConcateArray(passwordData, hashParts.DataAsByteArray))),
                AlgSha512 => ArraysEquals(hashParts.HashAsByteArray, HashSha512(passwordData)),
                AlgSha512Salt => ArraysEquals(hashParts.HashAsByteArray, HashSha512(ConcateArray(passwordData, hashParts.DataAsByteArray))),
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
