using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vespertan.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace Vespertan.Cryptography.Tests
{
    [TestClass()]
    public class CryptoStringsTests
    {
        [TestMethod()]
        public void GetCertStringTest()
        {
            var cert = new X509Certificate2("cert_with_key.pfx", "0okm)OKM");
            var data = "testData";
            var cryptoString = CryptoStrings.GetCertCryptoString(data, cert);
            var outData = CryptoStrings.DecryptCertText(cryptoString, cert);
            Assert.AreEqual(data, outData);
        }

        [TestMethod()]
        public void GetCertStringTest2()
        {
            var cert = new X509Certificate2("cert_with_key.pfx", "0okm)OKM");
            var cert2 = new X509Certificate2("certificate.crt");
            var data = "testData";
            var cryptoString = CryptoStrings.GetCertCryptoString(data, cert2);
            var outData = CryptoStrings.DecryptCertText(cryptoString, cert);
            Assert.AreEqual(data, outData);
        }

        [TestMethod()]
        public void GetSignStringTest()
        {
            var privCert = new X509Certificate2("cert_with_key.pfx", "0okm)OKM");
            var pubCert = new X509Certificate2("certificate.crt");
            var data = "testData";
            var cryptoString = CryptoStrings.GetSignCryptoString(data, privCert);
            var outData = CryptoStrings.GetSignText(cryptoString, pubCert);
            Assert.AreEqual(data, outData);

        }

        [TestMethod()]
        public void EncryptDataAesTest()
        {
            var salt = new byte[] { 3, 4 };
            CryptoStrings.EncryptAes(new byte[] { 1 }, new byte[] { 2, 3 }, ref salt);
        }

        [TestMethod()]
        public void DecryptDataAesTest()
        {
            var data = new byte[] { 1, 2 };
            var salt = new byte[] { 3, 4 };
            var hash = CryptoStrings.EncryptAes(data, new byte[] { 2, 3 }, ref salt);
            var decrypted = CryptoStrings.DecryptAes(hash, new byte[] { 2, 3 }, new byte[] { 3, 4 });
            CollectionAssert.AreEqual(decrypted, data);
        }

        [TestMethod()]
        public void EncryptDataAesHashTest()
        {
            var message = "crypto message";
            var cs = CryptoStrings.GetAesCryptoString(message, "pass");
            var roundtrip = CryptoStrings.DecryptAesText(cs, "pass");
            Assert.AreEqual(message, roundtrip);
        }

        [TestMethod()]
        public void DecryptTextTest()
        {
            var privCert = new X509Certificate2("cert_with_key.pfx", "0okm)OKM");
            var pubCert = new X509Certificate2("certificate.crt");
            var data = "testData";
            var cryptoString = CryptoStrings.GetCertCryptoString(data, pubCert);
            var outData = CryptoStrings.DecryptData(cryptoString, privateKey:privCert.GetRSAPrivateKey());
            Assert.AreEqual(data, outData);
        }
    }
}