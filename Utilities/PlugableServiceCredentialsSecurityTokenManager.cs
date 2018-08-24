// ----------------------------------------------------------------------------
// Copyright (C) 2008 Microsoft Corporation, All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;

namespace WCFSecurityUtilities
{
    public class PlugableServiceCredentialsSecurityTokenManager : ServiceCredentialsSecurityTokenManager
    {
        PlugableCredentialHelper _plugableCredentialHelper;
        ISecurityTokenSerializerFactory securityTokenSerializer;

        public PlugableServiceCredentialsSecurityTokenManager(ServiceCredentials creds)
            : base(creds)
        {
            _plugableCredentialHelper = new PlugableCredentialHelper();
        }

        public PlugableServiceCredentialsSecurityTokenManager CloneCore()
        {
            return new PlugableServiceCredentialsSecurityTokenManager(base.ServiceCredentials)
            {
                _plugableCredentialHelper = _plugableCredentialHelper.CloneCore(),
                securityTokenSerializer = this.securityTokenSerializer
            };
        }

        public void SetSecurityTokenAuthenticator(string tokenType, SecurityTokenAuthenticator authenticator, SecurityTokenResolver resolver)
        {
            if (tokenType == null)
                throw new ArgumentNullException("tokenType");

            if (authenticator == null)
                throw new ArgumentNullException("authenticator");

            if (resolver == null)
                throw new ArgumentNullException("resolver");

            _plugableCredentialHelper.SetSecurityTokenAuthenticator(tokenType, authenticator, resolver);
        }

        public void SetSecurityTokenProvider(string tokenType, SecurityTokenProvider provider)
        {
            if (tokenType == null)
                throw new ArgumentNullException("tokenType");

            if (provider == null)
                throw new ArgumentNullException("provider");

            _plugableCredentialHelper.SetSecurityTokenProvider(tokenType, provider);
        }

        public void SetSecurityTokenSerializer(ISecurityTokenSerializerFactory serializer)
        {
            if (serializer == null)
                throw new ArgumentNullException("serializer");

            this.securityTokenSerializer = serializer;
        }

        public override SecurityTokenAuthenticator CreateSecurityTokenAuthenticator(SecurityTokenRequirement requirement, out SecurityTokenResolver resolver)
        {
            if (requirement == null)
                throw new ArgumentNullException("requirement");

            SecurityTokenAuthenticator authenticator;

            if (_plugableCredentialHelper.TryGetSecurityTokenAuthenticator(requirement.TokenType, out authenticator, out resolver))
            {
                return authenticator;
            }
            
            SecurityTokenAuthenticator sta = base.CreateSecurityTokenAuthenticator(requirement, out resolver);

            if (requirement.TokenType == ServiceModelSecurityTokenTypes.SecureConversation)
                SetMySCTResolver(sta);

            return sta;
            
        }

        void SetMySCTResolver(SecurityTokenAuthenticator sta)
        {
            //return;
            Type type = ReflectionHelper.GetTypeSec("SecuritySessionSecurityTokenAuthenticator");
            object obj = ReflectionHelper.NewSec("SecuritySessionSecurityTokenAuthenticator", null);
            object objTokenCache = ReflectionHelper.GetProperty(type, sta, "IssuedTokenCache");
            SctResolver sctResolver = new SctResolver(objTokenCache as SecurityContextSecurityTokenResolver);
            ReflectionHelper.SetProperty(sta, "IssuedTokenCache", sctResolver);
            return;
        }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement requirement)
        {
            if (requirement == null)
                throw new ArgumentNullException(nameof(requirement));


            if (_plugableCredentialHelper.TryGetSecurityTokenProvider(requirement.TokenType, out SecurityTokenProvider provider))
                return provider;

            return base.CreateSecurityTokenProvider(requirement);
        }

        public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion stv)
        {
        
            if (this.securityTokenSerializer != null)
            {
                foreach (String spec in stv.GetSecuritySpecifications())
                {
                    if (spec == "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
                    {
                        return this.securityTokenSerializer.Create(SecurityVersion.WSSecurity10);
                    }
                }
                
                return this.securityTokenSerializer.Create(SecurityVersion.WSSecurity11);                
            }

            return base.CreateSecurityTokenSerializer(stv);
        }
    }
}
