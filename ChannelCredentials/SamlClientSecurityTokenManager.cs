//-----------------------------------------------------------------------------
//
// Copyright 2010 (c) Microsoft Corporation. All rights reserved.
//
//-----------------------------------------------------------------------------

using System.IdentityModel.Selectors;
using System.ServiceModel;

namespace IssuedToken
{
    public class SamlClientSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        public SamlClientSecurityTokenManager(SamlClientCredentials clientCredentials)
            : base(clientCredentials)
        { }

        /// <summary>
        /// Make use of this extensibility point for returning a custom SecurityTokenProvider when SAML tokens are specified in the tokenRequirement
        /// </summary>
        /// <param name="tokenRequirement">A SecurityTokenRequirement  </param>
        /// <returns>The appropriate SecurityTokenProvider</returns>
        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            // If token requirement matches SAML token return the custom SAML token provider            
            // that performs custom work to serve up the token
            if (tokenRequirement.TokenType == "urn:oasis:names:tc:SAML:2.0:assertion")
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
}
