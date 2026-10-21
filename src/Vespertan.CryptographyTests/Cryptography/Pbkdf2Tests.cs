using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Vespertan.Cryptography.Tests
{
    [TestClass]
    public class Pbkdf2Tests
    {
        private static readonly byte[] Salt = Encoding.ASCII.GetBytes("0123456789abcdef");

        [DataTestMethod]
        // RFC 7914 section 11, first 32 bytes of each 64-byte result.
        [DataRow("passwd", "salt", 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")]
        [DataRow("Password", "NaCl", 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56")]
        public void MatchesRfc7914(string password, string salt, int iterations, string expected)
        {
            var actual = CryptoStrings.HashPbkdf2(password, Encoding.ASCII.GetBytes(salt), iterations);
            Assert.AreEqual(expected, BitConverter.ToString(actual).Replace("-", "").ToLowerInvariant());
        }

        [DataTestMethod]
        // Independently generated with Rfc2898DeriveBytes, SHA256, UTF-8, 2 iterations.
        [DataRow("", "7bf3af78d2c914bbf55a6bd6dc451415e3b107dd608139b3700ae614a65c5b89")]
        [DataRow("zażółć gęślą jaźń 🔐", "70caad18efe683866d5dc3fc3e7ef02d26b171b0e1cf6ae9b4b8ab53e497e291")]
        [DataRow("pass\0word", "86259d5368187131f0e2252e7e6318dc7596bdc78ac52933eec6c0e3164a76f9")]
        public void MatchesIndependentUtf8Vectors(string password, string expected)
        {
            var actual = CryptoStrings.HashPbkdf2(password, Salt, 2);
            Assert.AreEqual(expected, BitConverter.ToString(actual).Replace("-", "").ToLowerInvariant());
        }

        [TestMethod]
        public void DefaultRecordUsesRandomSaltAndVerifiesThroughExistingApi()
        {
            var first = CryptoStrings.GetPbkdf2CryptoString("hasło 🔐");
            var second = CryptoStrings.GetPbkdf2CryptoString("hasło 🔐");
            Assert.AreNotEqual(first, second);
            Assert.AreNotEqual(first.Split(';').Last(), second.Split(';').Last());
            StringAssert.Contains(first, "$1;SHA256;600000;");
            Assert.AreEqual(16, Convert.FromBase64String(first.Split(';').Last()).Length);
            Assert.IsTrue(CryptoStrings.ValidatePasswordString("hasło 🔐", first));
            Assert.IsFalse(CryptoStrings.ValidatePasswordString("inne hasło", first));
            Assert.IsTrue(CryptoStrings.VerifyPbkdf2CryptoString("hasło 🔐", second));
            Assert.IsTrue(CryptoStrings.IsValidCryptoString(first));
            var parts = CryptoStrings.GetHashParts(first);
            Assert.AreEqual(CryptoType.Pbkdf2, parts.Type);
            Assert.AreEqual(32, parts.Hash.Length);
            CollectionAssert.AreEqual(parts.Hash, CryptoStrings.DecryptData(first, (byte[])null));
            Assert.IsFalse(CryptoStrings.NeedsPbkdf2Rehash(first));
            Assert.IsTrue(CryptoStrings.NeedsPbkdf2Rehash(first, 700000));
        }

        [TestMethod]
        public void ExplicitSaltAndIterationsAreDeterministicAndCultureIndependent()
        {
            var previous = Thread.CurrentThread.CurrentCulture;
            try
            {
                Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
                var saltCopy = (byte[])Salt.Clone();
                var record = CryptoStrings.GetPbkdf2CryptoString("password", saltCopy, 600001);
                CollectionAssert.AreEqual(Salt, saltCopy);
                Assert.AreEqual(record, CryptoStrings.GetPbkdf2CryptoString("password", Salt, 600001));
                StringAssert.Contains(record, ";600001;");
                Assert.IsTrue(CryptoStrings.VerifyPbkdf2CryptoString("password", record));
                Assert.IsFalse(CryptoStrings.NeedsPbkdf2Rehash(record));
            }
            finally
            {
                Thread.CurrentThread.CurrentCulture = previous;
            }
        }

        [DataTestMethod]
        [DataRow("")]
        [DataRow("zażółć gęślą jaźń 🔐")]
        [DataRow("pass\0word")]
        [DataRow("é")]
        [DataRow("e\u0301")]
        public void PreservesWholeUtf8Password(string password)
        {
            var record = HistoricalRecord(password, 2);
            Assert.IsTrue(CryptoStrings.VerifyPbkdf2CryptoString(password, record));
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString(password + "x", record));
            Assert.IsTrue(CryptoStrings.NeedsPbkdf2Rehash(record));
        }

        [TestMethod]
        public void DoesNotTruncateLongPasswordsOrNormalizeUnicode()
        {
            var password = new string('x', 10000);
            var record = HistoricalRecord(password, 2);
            Assert.AreEqual("bbb3ba621ea53fb43ca041e42f2ae0e0bc6154182cef676cd85860f91a4adc7c",
                BitConverter.ToString(CryptoStrings.GetHashParts(record).Hash).Replace("-", "").ToLowerInvariant());
            Assert.IsTrue(CryptoStrings.VerifyPbkdf2CryptoString(password, record));
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString(password + "y", record));
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("e\u0301", HistoricalRecord("é", 2)));
        }

        [TestMethod]
        public void RejectsIllFormedUnicodeWithoutReplacementCollisions()
        {
            Assert.ThrowsException<EncoderFallbackException>(() => CryptoStrings.HashPbkdf2("\ud800", Salt, 2));
            Assert.ThrowsException<EncoderFallbackException>(() => CryptoStrings.GetPbkdf2CryptoString("\udfff", Salt));
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("\ud800", HistoricalRecord("\ufffd", 2)));
        }

        [TestMethod]
        public void RejectsTamperingAtEveryHashByteAndInSaltOrIterations()
        {
            var record = HistoricalRecord("password", 2);
            var original = CryptoStrings.GetHashParts(record).Hash;
            for (var i = 0; i < original.Length; i++)
            {
                var changed = (byte[])original.Clone();
                changed[i] ^= 1;
                Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("password",
                    record.Replace(Convert.ToBase64String(original), Convert.ToBase64String(changed))));
            }
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("password", record.Replace(";2;", ";3;")));
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("password",
                record.Replace(Convert.ToBase64String(Salt), Convert.ToBase64String(new byte[16]))));
        }

        [DataTestMethod]
        [DataRow("0")]
        [DataRow("-1")]
        [DataRow("2000001")]
        [DataRow("2147483647")]
        [DataRow("2147483648")]
        [DataRow("+2")]
        [DataRow("02")]
        [DataRow(" 2")]
        [DataRow("2 ")]
        [DataRow("2.0")]
        [DataRow("")]
        [DataRow("٢")]
        public void RejectsInvalidWorkFactorsBeforeDerivation(string iterations)
        {
            AssertMalformed("$Pbkdf2$" + Convert.ToBase64String(new byte[32])
                + "$1;SHA256;" + iterations + ";" + Convert.ToBase64String(Salt));
        }

        [TestMethod]
        public void RejectsMalformedVersionAlgorithmLengthsBase64AndFields()
        {
            var record = HistoricalRecord("password", 2);
            var hash = record.Split('$')[2];
            foreach (var invalid in new[]
            {
                "$Pbkdf2$", record + "$extra", record + ";extra", record + "\n",
                record.Replace("$1;", "$2;"), record.Replace("SHA256", "SHA1"),
                record.Replace("SHA256", "sha256"), record.Replace(hash, "!" + hash.Substring(1)),
                record.Replace(hash, Convert.ToBase64String(new byte[31])),
                record.Replace(hash, Convert.ToBase64String(new byte[33])),
                record.Replace(Convert.ToBase64String(Salt), "!!!"),
                record.Replace(Convert.ToBase64String(Salt), Convert.ToBase64String(new byte[15])),
                record.Replace(Convert.ToBase64String(Salt), Convert.ToBase64String(new byte[65])),
                record.Replace(Convert.ToBase64String(Salt), ""),
                "$Pbkdf2$" + new string('A', 1000000)
            }) AssertMalformed(invalid);
        }

        [TestMethod]
        public void ValidatesArgumentsAndNulls()
        {
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString(null, HistoricalRecord("password", 2)));
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("password", null));
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("password", ""));
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("password", "$None$password"));
            Assert.IsTrue(CryptoStrings.NeedsPbkdf2Rehash(null));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.HashPbkdf2(null, Salt));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.HashPbkdf2("p", null));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.GetPbkdf2CryptoString(null));
            Assert.ThrowsException<ArgumentNullException>(() => CryptoStrings.GetPbkdf2CryptoString("p", null));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.HashPbkdf2("p", new byte[0]));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.HashPbkdf2("p", new byte[65]));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.HashPbkdf2("p", Salt, 0));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.HashPbkdf2("p", Salt, 2000001));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.GetPbkdf2CryptoString("p", new byte[15]));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.GetPbkdf2CryptoString("p", new byte[65]));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.GetPbkdf2CryptoString("p", Salt, 599999));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.GetPbkdf2CryptoString("p", Salt, 2000001));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => CryptoStrings.NeedsPbkdf2Rehash("", 599999));
        }

        [TestMethod]
        public void AcceptsMaximumSupportedParameters()
        {
            var record = CryptoStrings.GetPbkdf2CryptoString("password", new byte[64], 2000000);
            Assert.IsTrue(CryptoStrings.IsValidCryptoString(record));
            Assert.IsTrue(CryptoStrings.VerifyPbkdf2CryptoString("password", record));
            Assert.IsFalse(CryptoStrings.NeedsPbkdf2Rehash(record));
        }

        [TestMethod]
        public void LegacyPasswordFormatsStillVerify()
        {
            var password = "legacy";
            foreach (var record in new[]
            {
                CryptoStrings.GetNoneCryptoString(password), CryptoStrings.GetNoneCryptoString(Encoding.UTF8.GetBytes(password)),
                CryptoStrings.GetMd5CryptoString(password), CryptoStrings.GetMd5SaltedCryptoString(password, Salt),
                CryptoStrings.GetSha1CryptoString(password), CryptoStrings.GetSha1SaltedCryptoString(password, Salt),
                CryptoStrings.GetSha256CryptoString(password), CryptoStrings.GetSha256SaltedCryptoString(password, Salt),
                CryptoStrings.GetSha384CryptoString(password), CryptoStrings.GetSha384SaltedCryptoString(password, Salt),
                CryptoStrings.GetSha512CryptoString(password), CryptoStrings.GetSha512SaltedCryptoString(password, Salt)
            })
            {
                Assert.IsTrue(CryptoStrings.ValidatePasswordString(password, record));
                Assert.IsFalse(CryptoStrings.ValidatePasswordString("wrong", record));
                Assert.IsTrue(CryptoStrings.NeedsPbkdf2Rehash(record));
            }
        }

        private static string HistoricalRecord(string password, int iterations)
        {
            return "$Pbkdf2$" + Convert.ToBase64String(CryptoStrings.HashPbkdf2(password, Salt, iterations))
                + "$1;SHA256;" + iterations.ToString(CultureInfo.InvariantCulture) + ";" + Convert.ToBase64String(Salt);
        }

        private static void AssertMalformed(string record)
        {
            Assert.IsFalse(CryptoStrings.VerifyPbkdf2CryptoString("password", record));
            Assert.IsFalse(CryptoStrings.ValidatePasswordString("password", record));
            Assert.IsFalse(CryptoStrings.IsValidCryptoString(record));
            Assert.ThrowsException<FormatException>(() => CryptoStrings.GetHashParts(record));
        }
    }
}
