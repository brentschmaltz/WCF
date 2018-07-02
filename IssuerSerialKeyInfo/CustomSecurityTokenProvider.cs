
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.

using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace WCFSecurityUtilities
{
    public class CustomSecurityTokenProvider : SecurityTokenProvider
    {

        public CustomSecurityTokenProvider()
        {
        }

        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            return null;
        }
    }
}
