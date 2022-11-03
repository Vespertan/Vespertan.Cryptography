using System;
using System.Collections.Generic;
using System.Text;

namespace Vespertan.Cryptography
{
    public enum PasswordType
    {
        None,
        Sha1,
        Md5,
        Sha256,
        Sha384,
        Sha512,
        Sha1Salt,
        Md5Salt,
        Sha256Salt,
        Sha384Salt,
        Sha512Salt,
    }
}
