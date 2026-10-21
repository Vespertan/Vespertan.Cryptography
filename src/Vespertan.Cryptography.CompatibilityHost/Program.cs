using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Vespertan.Cryptography;
using Vespertan.Cryptography.Tests;

// Integration-test executable: each target runs in its own runtime and exchanges fresh records.
internal static class Program
{
#if NET48
    private const string Target = "net48";
#else
    private const string Target = "net10.0";
#endif
    private const string Password = "hasło 🔐\0" + "0123456789012345678901234567890123456789";
    private const string Text = "Zażółć gęślą jaźń 🔐\0koniec";
    private static readonly byte[] Data = Enumerable.Range(0, 1024).Select(i => (byte)i).ToArray();

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length != 2 || (args[0] != "write" && args[0] != "verify"))
                throw new ArgumentException("Usage: CompatibilityHost write|verify <exchange-file>");
            using var privateCertificate = TestCertificates.LoadPrivate();
            using var publicCertificate = TestCertificates.LoadPublic();
            using var privateKey = privateCertificate.GetRSAPrivateKey();
            using var publicKey = publicCertificate.GetRSAPublicKey();
            if (args[0] == "write")
            {
                var records = new Dictionary<string, string>
                {
                    ["writer"] = Target,
                    ["pbkdf2"] = CryptoStrings.GetPbkdf2CryptoString(Password, 600001),
                    ["authenticated-empty"] = CryptoStrings.GetAuthenticatedAesCryptoString("", Password),
                    ["authenticated-text"] = CryptoStrings.GetAuthenticatedAesCryptoString(Text, Password, 600001),
                    ["authenticated-binary"] = CryptoStrings.GetAuthenticatedAesCryptoString(Data, Password),
                    ["legacy-aes"] = CryptoStrings.GetAesCryptoString(Data, Password),
                    ["cert"] = CryptoStrings.GetCertCryptoString(Data, publicKey, publicCertificate.Thumbprint),
                    ["sign"] = CryptoStrings.GetSignCryptoString(Data, privateKey, privateCertificate.Thumbprint)
                };
                foreach (var saltLength in Enumerable.Range(1, 16))
                {
                    var salt = Salt(saltLength);
                    records["raw-" + saltLength] = Convert.ToBase64String(CryptoStrings.HashPbkdf2(Password, salt, 2));
                    records["raw-empty-" + saltLength] = Convert.ToBase64String(CryptoStrings.HashPbkdf2("", salt, 2));
                }
                File.WriteAllLines(args[1], records.Select(pair => pair.Key + "\t" + pair.Value));
                Console.WriteLine(Target + " wrote " + (records.Count - 1) + " records; runtime " + Environment.Version);
            }
            else
            {
                var records = File.ReadAllLines(args[1]).Select(line => line.Split(new[] { '\t' }, 2))
                    .ToDictionary(parts => parts[0], parts => parts[1]);
                Require(records["writer"] == (Target == "net48" ? "net10.0" : "net48"), "opposite target required");
                Require(records.Count == 40, "complete exchange required");
                Require(CryptoStrings.VerifyPbkdf2CryptoString(Password, records["pbkdf2"]), "PBKDF2");
                Require(!CryptoStrings.VerifyPbkdf2CryptoString("wrong", records["pbkdf2"]), "wrong password");
                Require(CryptoStrings.DecryptAuthenticatedAesText(records["authenticated-empty"], Password) == "", "empty AES");
                Require(CryptoStrings.DecryptAuthenticatedAesText(records["authenticated-text"], Password) == Text, "text AES");
                Require(Data.SequenceEqual(CryptoStrings.DecryptData(records["authenticated-binary"], Password)), "binary AES");
                Require(Data.SequenceEqual(CryptoStrings.DecryptAesData(records["legacy-aes"], Password)), "legacy AES");
                Require(Data.SequenceEqual(CryptoStrings.DecryptData(records["cert"], privateKey)), "certificate");
                Require(Data.SequenceEqual(CryptoStrings.GetSignData(records["sign"], publicCertificate)), "signature");
                foreach (var saltLength in Enumerable.Range(1, 16))
                {
                    var salt = Salt(saltLength);
                    Require(records["raw-" + saltLength] == Convert.ToBase64String(CryptoStrings.HashPbkdf2(Password, salt, 2)),
                        "raw PBKDF2 salt " + saltLength);
                    Require(records["raw-empty-" + saltLength] == Convert.ToBase64String(CryptoStrings.HashPbkdf2("", salt, 2)),
                        "empty PBKDF2 salt " + saltLength);
                }
                ExpectCryptoFailure(() => CryptoStrings.DecryptAuthenticatedAesData(records["authenticated-binary"], "wrong"));
                var fields = records["authenticated-binary"].Split('$');
                var envelope = Convert.FromBase64String(fields[2]);
                envelope[envelope.Length - 1] ^= 1;
                ExpectCryptoFailure(() => CryptoStrings.DecryptData("$AesAuthenticated$" + Convert.ToBase64String(envelope), Password));
                Console.WriteLine(records["writer"] + " -> " + Target + ": 39 records verified, wrong password and tampering rejected.");
            }
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(Target + ": " + exception);
            return 1;
        }
    }

    private static byte[] Salt(int length) => Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
    private static void Require(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException("Compatibility check failed: " + description);
    }
    private static void ExpectCryptoFailure(Action action)
    {
        try { action(); }
        catch (CryptographicException) { return; }
        throw new InvalidOperationException("Invalid authenticated record was accepted.");
    }
}
