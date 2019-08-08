using System.IdentityModel.Selectors;
using System.Security.Cryptography.X509Certificates;

namespace WCFSecurityUtilities
{
    public class CertValidatorAlwaysSucceed : X509CertificateValidator
    {

        public override void Validate(X509Certificate2 certificate)
        {
            return;
        }
    }
}
