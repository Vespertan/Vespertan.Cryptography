using System;

namespace Vespertan.Cryptography
{
    public enum PasswordType
    {
        None = 0,
        Sha1 = 1,
        Md5 = 2,
        Sha256 = 3,
        Sha384 = 4,
        Sha512 = 5,
        Sha1Salt = 6,
        Md5Salt = 7,
        Sha256Salt = 8,
        Sha384Salt = 9,
        Sha512Salt = 10,
        Aes = 11,
        Cert = 12,
        Sign = 13,
    }
}
