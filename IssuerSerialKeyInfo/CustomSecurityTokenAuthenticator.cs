// ----------------------------------------------------------------------------
// Copyright (C) 2008 Microsoft Corporation, All rights reserved.
// ----------------------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;

namespace WCFSecurityUtilities
{
    public class CustomSecurityTokenAuthenticator : SecurityTokenAuthenticator
    {
        ReadOnlyCollection<IAuthorizationPolicy> policies;

        public CustomSecurityTokenAuthenticator()
        {
            List<IAuthorizationPolicy> authPolicies = new List<IAuthorizationPolicy>();
            //authPolicies.Add(new CustomSecurityAuthorizationPolicy());
            policies = authPolicies.AsReadOnly();
        }

        protected override bool CanValidateTokenCore(SecurityToken token)
        {
            //if (token is CustomSecurityToken)
                return true;

            //GenericXmlSecurityToken genToken = token as GenericXmlSecurityToken;
            //if (genToken == null)
            //    return false;

            //if (genToken.ProofToken is CustomSecurityToken)
            //    return true;

            //return false;
        }

        protected override ReadOnlyCollection<IAuthorizationPolicy> ValidateTokenCore(SecurityToken token)
        {
            return policies;
        }
    }
}
