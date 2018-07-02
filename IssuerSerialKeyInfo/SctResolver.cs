// ----------------------------------------------------------------------------
// Copyright (C) 2008 Microsoft Corporation, All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Xml;

namespace WCFSecurityUtilities
{
    public class SctResolver : SecurityTokenResolver, ISecurityContextSecurityTokenCache
    {
        SecurityContextSecurityTokenResolver _innerSctResolver;

        public SctResolver(SecurityContextSecurityTokenResolver innerSctResolver)
        {
            _innerSctResolver = innerSctResolver;
        }
       
        public bool RemoveOldestTokensOnCacheFull
        {
            get
            {
                return _innerSctResolver.RemoveOldestTokensOnCacheFull;
            }
        }

        public void AddContext(SecurityContextSecurityToken token)
        {
            _innerSctResolver.AddContext(token);
        }
        
        public bool TryAddContext(SecurityContextSecurityToken token)
        {
            return _innerSctResolver.TryAddContext(token);
        }

        public void ClearContexts()
        {
            _innerSctResolver.ClearContexts();
        }

        public void RemoveContext(UniqueId contextId, UniqueId generation)
        {
            _innerSctResolver.RemoveContext(contextId, generation);
        }

        public void RemoveAllContexts(UniqueId contextId)
        {
            _innerSctResolver.RemoveAllContexts(contextId);
        }

        public SecurityContextSecurityToken GetContext(UniqueId contextId, UniqueId generation)
        {
            return _innerSctResolver.GetContext(contextId, generation);
        }

        public Collection<SecurityContextSecurityToken> GetAllContexts(UniqueId contextId)
        {
            return _innerSctResolver.GetAllContexts(contextId);
        }

        public void UpdateContextCachingTime(SecurityContextSecurityToken context, DateTime expirationTime)
        {
            _innerSctResolver.UpdateContextCachingTime(context, expirationTime);
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token)
        {
            SecurityContextKeyIdentifierClause sctSkiClause = keyIdentifierClause as SecurityContextKeyIdentifierClause;
            if (sctSkiClause != null)
            {
                token = _innerSctResolver.GetContext(sctSkiClause.ContextId, sctSkiClause.Generation);
            }
            else
            {
                token = null;
            }
            return (token != null);
        }

        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            SecurityToken sct;
            if (TryResolveTokenCore(keyIdentifierClause, out sct))
            {
                key = ((SecurityContextSecurityToken)sct).SecurityKeys[0];
                return true;
            }
            else
            {
                key = null;
                return false;
            }
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifier keyIdentifier, out SecurityToken token)
        {
            SecurityContextKeyIdentifierClause sctSkiClause;
            if (keyIdentifier.TryFind<SecurityContextKeyIdentifierClause>(out sctSkiClause))
            {
                return TryResolveToken(sctSkiClause, out token);
            }
            else
            {
                token = null;
                return false;
            }
        }
    }
}
