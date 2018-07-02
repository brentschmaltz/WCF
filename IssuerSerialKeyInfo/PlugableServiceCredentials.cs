// ----------------------------------------------------------------------------
// Copyright (C) 2008 Microsoft Corporation, All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.IdentityModel.Selectors;
using System.ServiceModel;
using System.ServiceModel.Description;

namespace WCFSecurityUtilities
{
    public class PlugableServiceCredentials : ServiceCredentials
    {
        ServiceCredentials serviceCredentialsBase;
        ServiceHost serviceHost;
        PlugableServiceCredentialsSecurityTokenManager internalSecurityTokenManager;

        public PlugableServiceCredentials(ServiceHost serviceHost)
            : base(serviceHost.Credentials)
        {
            if (serviceHost == null)
                throw new ArgumentNullException("serviceHost");

            this.serviceCredentialsBase = serviceHost.Credentials;
            this.serviceHost = serviceHost;
            this.internalSecurityTokenManager = new PlugableServiceCredentialsSecurityTokenManager(this);
            serviceHost.Description.Behaviors.Remove<ServiceCredentials>();
            serviceHost.Description.Behaviors.Add(this);
        }

        public void SetSecurityTokenAuthenticator(string tokenType, SecurityTokenAuthenticator authenticator, SecurityTokenResolver resolver)
        {
            if (this.internalSecurityTokenManager == null)
                throw new InvalidOperationException("internalSecurityTokenManager is null");

            this.internalSecurityTokenManager.SetSecurityTokenAuthenticator(tokenType, authenticator, resolver);
        }

        public void SetSecuriyTokenProvider(string tokenType, SecurityTokenProvider provider)
        {
            if (this.internalSecurityTokenManager == null)
                throw new InvalidOperationException("internalSecurityTokenManager is null");

            this.internalSecurityTokenManager.SetSecurityTokenProvider(tokenType, provider);
        }

        public void SetSecuriyTokenSerializer(ISecurityTokenSerializerFactory serializer)
        {
            if (this.internalSecurityTokenManager == null)
                throw new InvalidOperationException("internalSecurityTokenManager is null");

            this.internalSecurityTokenManager.SetSecurityTokenSerializer(serializer);
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return this.internalSecurityTokenManager;
        }

        protected override ServiceCredentials CloneCore()
        {
            PlugableServiceCredentials clone = new PlugableServiceCredentials(this.serviceHost);
            clone.internalSecurityTokenManager = this.internalSecurityTokenManager.CloneCore();

            return clone;
        }
    }
}
