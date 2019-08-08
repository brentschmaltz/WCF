using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace WCFSecurityUtilities
{
    public class ServicePointManagerCallbacks
    {
        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool AcceptAllCertificates(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
