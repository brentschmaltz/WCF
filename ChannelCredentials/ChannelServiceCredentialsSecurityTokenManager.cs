
using System;
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;
using System.ServiceModel.Security;

namespace ChannelCredentials
{
    public class ChannelServiceCredentialsSecurityTokenManager : ServiceCredentialsSecurityTokenManager
    {
        public ChannelServiceCredentialsSecurityTokenManager(ServiceCredentials serviceCredentials)
            : base(serviceCredentials)
        {
        }

        public override SecurityTokenAuthenticator CreateSecurityTokenAuthenticator(SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver)
        {
            return base.CreateSecurityTokenAuthenticator(tokenRequirement, out outOfBandTokenResolver);
        }
    }
}
