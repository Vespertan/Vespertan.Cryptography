using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vespertan.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vespertan.Cryptography.Tests
{
    [TestClass()]
    public class CryptoStringTests
    {
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

    }
}