using System;
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;

namespace ChannelCredentials
{
    public class ChannelServiceCredentials : ServiceCredentials
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public ChannelServiceCredentials(ServiceCredentials serviceCredentials)
            : base(serviceCredentials)
        {
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">The SamlClientCredentials to create a copy of</param>
        protected ChannelServiceCredentials(ChannelServiceCredentials other)
            : base(other)
        {
        }

        protected override ServiceCredentials CloneCore()
        {
            return new ChannelServiceCredentials(this);
        }

        /// <summary>
        /// Extensibility point for serving up the <see cref="SecurityTokenManager"/>.
        /// </summary>
        /// <returns>the <see cref="SecurityTokenManager"/> that was passed in constructor.</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new ChannelServiceCredentialsSecurityTokenManager(this);
        }
    }
}
