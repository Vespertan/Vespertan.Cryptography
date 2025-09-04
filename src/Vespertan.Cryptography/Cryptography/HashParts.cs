using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vespertan.Cryptography
{
    public class HashParts
    {
        public HashParts(string hash)
        {
            if (string.IsNullOrEmpty(hash))
            {
                throw new ArgumentNullException(nameof(hash));
            }

            if (hash[0] != '$')
            {
                throw new InvalidOperationException("Invalid hash");
            }
            var startOfHashindex = hash.IndexOf('$', 1);
            if (startOfHashindex == -1)
            {
                throw new InvalidOperationException("Invalid hash");
            }
            var cryptoTypeString = hash.Substring(1, startOfHashindex - 1);
            Type = (CryptoType)Enum.Parse(typeof(CryptoType), cryptoTypeString, ignoreCase: true);
            if (Type == CryptoType.None)
            {
                Hash = Encoding.UTF8.GetBytes(hash.Substring(startOfHashindex + 1));
            }
            else
            {
                var startOfDataIndex = hash.IndexOf('$', startOfHashindex + 1);
                if (startOfDataIndex != -1)
                {
                    Data = hash.Substring(startOfDataIndex + 1);
                    Hash = Convert.FromBase64String(hash.Substring(startOfHashindex + 1, startOfDataIndex - startOfHashindex - 1));
                }
                else
                {
                    Data = null;
                    Hash = Convert.FromBase64String(hash.Substring(startOfHashindex + 1));
                }
            }
        }

        public static bool IsValidHash(string hash)
        {
            if (string.IsNullOrEmpty(hash))
            {
                return false;
            }

            if (hash[0] != '$')
            {
                return false;
            }
            
            var startOfHashindex = hash.IndexOf('$', 1);
            if (startOfHashindex == -1)
            {
                return false;
            }
            
            var cryptoTypeString = hash.Substring(1, startOfHashindex - 1);
            if (!Enum.TryParse<CryptoType>(cryptoTypeString, ignoreCase: true, out var cryptoType))
            {
                return false;
            }

            if (cryptoType == CryptoType.None)
            {
                return true;
            }
            else
            {
                var startOfDataIndex = hash.IndexOf('$', startOfHashindex + 1);
                if (startOfDataIndex != -1)
                {
                    var base64String = hash.Substring(startOfHashindex + 1, startOfDataIndex - startOfHashindex - 1);
                    try
                    {
                        Convert.FromBase64String(base64String);
                        return true;
                    }
                    catch
                    {
                        return false;
                    }
                }
                else
                {
                    var base64String = hash.Substring(startOfHashindex + 1);
                    try
                    {
                        Convert.FromBase64String(base64String);
                        return true;
                    }
                    catch
                    {
                        return false;
                    }
                }
            }
        }

        public CryptoType Type { get; set; }
        public string Data { get; set; }
        public byte[] Hash { get; set; }

        public byte[] DataAsByteArray => Data == null ? null : Convert.FromBase64String(Data);
    }
}
