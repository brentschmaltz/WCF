// ----------------------------------------------------------------------------
// Copyright (C) 2008 Microsoft Corporation, All rights reserved.
// ----------------------------------------------------------------------------

using System.IdentityModel.Selectors;
using System.ServiceModel.Security;

namespace WCFSecurityUtilities
{
    public interface ISecurityTokenSerializerFactory
    {
        SecurityTokenSerializer Create(SecurityVersion sv);
    }
}
