//-----------------------------------------------------------------------------
//
// Copyright 2010 (c) Microsoft Corporation. All rights reserved.
//
//-----------------------------------------------------------------------------

using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;

namespace ChannelCredentials
{
    /// <summary>
    /// Custom SamlSecurityTokenProvider that returns a SAML assertion
    /// </summary>
    public class SamlSecurityTokenProvider : SecurityTokenProvider
    {
        readonly SecurityTokenRequirement _tokenRequirement;

        public SamlSecurityTokenProvider( SecurityTokenRequirement tokenRequirement )
        {
            _tokenRequirement = tokenRequirement ?? throw new ArgumentNullException(nameof(tokenRequirement));
        }

        /// <summary>
        /// Calls out to the STS, if necessary to get a token
        /// </summary>
        protected override SecurityToken GetTokenCore( TimeSpan timeout )
        {
            throw new NotSupportedException("put saml token in here");
        }
    }
}
