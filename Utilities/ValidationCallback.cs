// ----------------------------------------------------------------------------
// Validation Callback for validation of certs
// ----------------------------------------------------------------------------

using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace WcfUtilities
{
    public class ValidationCallback
    {
        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors )
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine($"Certificate error: {sslPolicyErrors}");

            return true;
        }
    }
}
