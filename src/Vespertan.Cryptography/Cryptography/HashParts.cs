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
                Type = parts[0];
                Data = parts[1];
                Hash = parts[2];
            }
            else if (parts.Length == 2)
            {
                Type = parts[0];
                Hash = parts[1];
            }
            else
            {
                throw new InvalidOperationException("Invalid hash");
            }
        }
        public string Type { get; set; }
        public string Data { get; set; }
        public string Hash { get; set; }

        public byte[] DataAsByteArray => Convert.FromBase64String(Data);
        public byte[] HashAsByteArray => Convert.FromBase64String(Hash);
    }
}
