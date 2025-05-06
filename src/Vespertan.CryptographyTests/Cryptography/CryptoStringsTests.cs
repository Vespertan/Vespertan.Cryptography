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
    }
}