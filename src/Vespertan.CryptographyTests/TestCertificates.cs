using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Vespertan.Cryptography.Tests
{
    // Shared by unit tests and the cross-runtime compatibility host.
    internal static class TestCertificates
    {
        internal static X509Certificate2 LoadPrivate()
        {
            var path = Path.Combine(AppContext.BaseDirectory, "cert_with_key.pfx");
#if NET48
            return new X509Certificate2(path, "0okm)OKM");
#else
            return X509CertificateLoader.LoadPkcs12FromFile(path, "0okm)OKM");
#endif
        }

        internal static X509Certificate2 LoadPublic()
        {
            var path = Path.Combine(AppContext.BaseDirectory, "certificate.crt");
#if NET48
            return new X509Certificate2(path);
#else
            return X509CertificateLoader.LoadCertificateFromFile(path);
#endif
        }
    }
}
