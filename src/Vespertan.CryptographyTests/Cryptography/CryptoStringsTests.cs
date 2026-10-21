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
            var cert = TestCertificates.LoadPrivate();
            var data = "testData";
            var cryptoString = CryptoStrings.GetCertCryptoString(data, cert);
            var outData = CryptoStrings.DecryptCertText(cryptoString, cert);
            Assert.AreEqual(data, outData);
        }

        [TestMethod()]
        public void GetCertStringTest2()
        {
            var cert = TestCertificates.LoadPrivate();
            var cert2 = TestCertificates.LoadPublic();
            var data = "testData";
            var cryptoString = CryptoStrings.GetCertCryptoString(data, cert2);
            var outData = CryptoStrings.DecryptCertText(cryptoString, cert);
            Assert.AreEqual(data, outData);
        }

        [TestMethod()]
        public void GetSignStringTest()
        {
            var privCert = TestCertificates.LoadPrivate();
            var pubCert = TestCertificates.LoadPublic();
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
            using (var privCert = TestCertificates.LoadPrivate())
            using (var pubCert = TestCertificates.LoadPublic())
            using (var privateKey = privCert.GetRSAPrivateKey())
            {
                var data = "testData — zażółć 🔐";
                var cryptoString = CryptoStrings.GetCertCryptoString(data, pubCert);
                var outData = CryptoStrings.DecryptData(cryptoString, privateKey);
                CollectionAssert.AreEqual(Encoding.UTF8.GetBytes(data), outData);
                Assert.AreEqual(data, CryptoStrings.DecryptText(cryptoString, (byte[])null, privateKey));
                Assert.AreEqual(data, CryptoStrings.DecryptText(cryptoString, (string)null, privateKey));
            }
        }
    }
}
