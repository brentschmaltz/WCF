using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace WCFSecurityUtilities
{
    public class CertValidatorAlwaysFail : X509CertificateValidator
    {

        public override void Validate(X509Certificate2 certificate)
        {
            throw new SecurityTokenValidationException("CertValidatorAlwaysFail: Cert is always bad");
        }
    }
}
