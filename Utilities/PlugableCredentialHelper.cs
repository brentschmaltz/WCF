// ----------------------------------------------------------------------------
// Copyright (C) 2008 Microsoft Corporation, All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;

namespace WCFSecurityUtilities
{
    public class PlugableCredentialHelper
    {
        Dictionary<string, SecurityTokenAuthenticator> authenticators;
        Dictionary<string, SecurityTokenProvider> providers;
        Dictionary<string, SecurityTokenResolver> resolvers;

        public PlugableCredentialHelper()
        {
            this.authenticators = new Dictionary<string, SecurityTokenAuthenticator>();
            this.providers = new Dictionary<string, SecurityTokenProvider>();
            this.resolvers = new Dictionary<string, SecurityTokenResolver>();
        }

        public PlugableCredentialHelper CloneCore()
        {
            PlugableCredentialHelper clone = new PlugableCredentialHelper();
          
            string[] authenticatorKeys = new string[this.authenticators.Count];
            this.authenticators.Keys.CopyTo(authenticatorKeys, 0);
            for (int i = 0; i < this.authenticators.Keys.Count; i++)
            {
                SecurityTokenAuthenticator sta;
                this.authenticators.TryGetValue(authenticatorKeys[i], out sta);
                clone.authenticators.Add(authenticatorKeys[i], sta);
            }

            string[] providerKeys = new string[this.providers.Count];
            this.providers.Keys.CopyTo(providerKeys, 0);
            for (int i = 0; i < this.providers.Keys.Count; i++)
            {
                SecurityTokenProvider stp;
                this.providers.TryGetValue(providerKeys[i], out stp);
                clone.providers.Add(providerKeys[i], stp);
            }

            string[] resolversKeys = new string[this.resolvers.Count];
            this.resolvers.Keys.CopyTo(resolversKeys, 0);
            for (int i = 0; i < this.resolvers.Keys.Count; i++)
            {
                SecurityTokenResolver str;
                this.resolvers.TryGetValue(resolversKeys[i], out str);
                clone.resolvers.Add(resolversKeys[i], str);
            }

            return clone;
        }

        public void SetSecurityTokenAuthenticator(string tokenType, SecurityTokenAuthenticator authenticator, SecurityTokenResolver resolver)
        {
            if (tokenType == null)
                throw new ArgumentNullException("tokenType");

            if (authenticator == null)
                throw new ArgumentNullException("authenticator");

            // $$TODO [brentsch] think about if this can be null
            if (resolver == null)
                throw new ArgumentNullException("resolver");

            if (this.authenticators.ContainsKey(tokenType))
                this.authenticators.Remove(tokenType);

            if (this.resolvers.ContainsKey(tokenType))
                this.resolvers.Remove(tokenType);

            this.authenticators.Add(tokenType, authenticator);
            this.resolvers.Add(tokenType, resolver);
        }

        public void SetSecurityTokenProvider(string tokenType, SecurityTokenProvider provider)
        {
            if (tokenType == null)
                throw new ArgumentNullException("tokenType");

            if (provider == null)
                throw new ArgumentNullException("provider");

            if (this.providers.ContainsKey(tokenType))
                this.providers.Remove(tokenType);

            this.providers.Add(tokenType, provider);
        }

        public bool TryGetSecurityTokenAuthenticator(string tokenType, out SecurityTokenAuthenticator authenticator, out SecurityTokenResolver resolver)
        {
            authenticator = null;
            resolver = null;

            if (authenticators.TryGetValue(tokenType, out authenticator))
            {
                resolvers.TryGetValue(tokenType, out resolver);
                return true;
            }

            return false;
        }

        public bool TryGetSecurityTokenProvider(string tokenType, out SecurityTokenProvider provider)
        {
            provider = null;
            return providers.TryGetValue(tokenType, out provider);
        }

    }
}
