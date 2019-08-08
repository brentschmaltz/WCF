using System.IdentityModel.Tokens;

namespace WCFSecurityUtilities
{

    public class ReturnX509SubjectNameOrRSAIssuerNameRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName( SecurityToken securityToken )
        {
            if (securityToken is X509SecurityToken x509Token)
            {
                return x509Token.Certificate.SubjectName.Name;
            }
            else if (securityToken is RsaSecurityToken rsaToken)
            {
                return string.Format("RSA-token-{0}", rsaToken.Rsa.ToXmlString(false));
            }

            return null;
        }
    }
}
