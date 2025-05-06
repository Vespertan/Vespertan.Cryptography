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
            var parts = hash.Split(new char[] { '$' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 3)
            {
                Type = (PasswordType)Enum.Parse(typeof(PasswordType), parts[0], ignoreCase: true);
                Hash = Convert.FromBase64String(parts[1]);
                Data = parts[2];
            }
            else if (parts.Length == 2)
            {
                Type = (PasswordType)Enum.Parse(typeof(PasswordType), parts[0], ignoreCase: true);
                Hash = Convert.FromBase64String(parts[1]);
            }
            else
            {
                throw new InvalidOperationException("Invalid hash");
            }
        }
        public PasswordType Type { get; set; }
        public string Data { get; set; }
        public byte[] Hash { get; set; }

        public byte[] DataAsByteArray => Data == null ? null : Convert.FromBase64String(Data);
    }
}
