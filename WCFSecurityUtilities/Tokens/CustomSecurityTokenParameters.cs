using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security.Tokens;

namespace WCFSecurityUtilities
{
    public class CustomSecurityTokenParameters : SecurityTokenParameters
    {
        protected override SecurityTokenParameters CloneCore()
        {
            return new CustomSecurityTokenParameters();
        }

        protected override SecurityKeyIdentifierClause CreateKeyIdentifierClause(SecurityToken token, SecurityTokenReferenceStyle referenceStyle)
        {
            CustomSecurityToken cst = token as CustomSecurityToken;
            if (cst != null)
            {
                if (referenceStyle == SecurityTokenReferenceStyle.Internal || referenceStyle == SecurityTokenReferenceStyle.External)
                    return (cst.CreateKeyIdentifierClause<LocalIdKeyIdentifierClause>());
                else
                    return (cst.CreateKeyIdentifierClause<CustomKeyIdentifierClause>());
            }

            throw new ArgumentException("Token must be of type CustomSecurityToken", "token");

        }

        protected override bool HasAsymmetricKey
        {
            get { return false; }
        }

        protected override bool MatchesKeyIdentifierClause(SecurityToken token, SecurityKeyIdentifierClause keyIdentifierClause, SecurityTokenReferenceStyle referenceStyle)
        {
            return ((CustomSecurityToken)token).MatchesKeyIdentifierClause(keyIdentifierClause);
        }

        protected override bool SupportsClientAuthentication
        {
            get { return false; }
        }

        protected override bool SupportsClientWindowsIdentity
        {
            get { return false; }
        }

        protected override bool SupportsServerAuthentication
        {
            get { return false; }
        }

        protected override void InitializeSecurityTokenRequirement(SecurityTokenRequirement requirement)
        {
            requirement.TokenType = TokenTypes.Saml11;
        }
    }
}
