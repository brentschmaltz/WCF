//-----------------------------------------------------------------------------
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//-----------------------------------------------------------------------------

using System.IdentityModel.Selectors;
using System.ServiceModel.Description;

namespace IssuedToken
{
    /// <summary>
    /// Custom client credentials class that will serve up a SamlSecurityTokenManager that in turn
    /// will serve up a custom SamlSecurityTokenProvider
    /// </summary>
    public class SamlClientCredentials : ClientCredentials
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public SamlClientCredentials()
            : base()
        {
            // Set SupportInteractive to false to suppress Cardspace UI
            base.SupportInteractive = false;
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">The SamlClientCredentials to create a copy of</param>
        protected SamlClientCredentials(SamlClientCredentials other) : base ( other )
        {
        }

        protected override ClientCredentials CloneCore()
        {
            return new SamlClientCredentials(this);            
        }

        /// <summary>
        /// Extensibility point for serving up the SamlSecurityTokenManager
        /// </summary>
        /// <returns>SamlSecurityTokenManager</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            // return custom security token manager
            return new SamlClientSecurityTokenManager(this);
        }
    }
}
