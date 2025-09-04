using System;

namespace Vespertan.Cryptography
{
    public enum CryptoType
    {
        None = 0,
        NoneData = 1,
        Sha1 = 2,
        Md5 = 3,
        Sha256 = 4,
        Sha384 = 5,
        Sha512 = 6,
        Sha1Salt = 7,
        Md5Salt = 8,
        Sha256Salt = 9,
        Sha384Salt = 10,
        Sha512Salt = 11,
        Aes = 12,
        Cert = 13,
        Sign = 14,
    }
}
