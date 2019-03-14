
using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;

namespace ChannelCredentials
{
    /// <summary>
    /// Extends <see cref="ClientCredentialsSecurityTokenManager"/> that can be used to return custom 
    /// </summary>
    public class ChannelClientCredentialsSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        public ChannelClientCredentialsSecurityTokenManager(ChannelClientCredentials clientCredentials)
            : base(clientCredentials)
        {
        }

        /// <summary>
        /// Returns a custom SecurityTokenProvider when SAML tokens are specified in the tokenRequirement
        /// </summary>
        /// <param name="tokenRequirement">A SecurityTokenRequirement  </param>
        /// <returns>The appropriate SecurityTokenProvider</returns>
        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            // If token requirement matches SAML token return the custom SAML token provider            
            // that performs custom work to serve up the token
            if (tokenRequirement.TokenType == SecurityTokenTypes.Saml)
            {
                return new SamlSecurityTokenProvider(tokenRequirement);
            }
            // otherwise use base implementation
            else
            {
                return base.CreateSecurityTokenProvider(tokenRequirement);
            }
        }
    }
}
