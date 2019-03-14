using System;
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;

namespace ChannelCredentials
{
    /// <summary>
    /// These client credentials class that will use a custom SecurityTokenManager
    /// to provide: 
    /// <see cref="SecurityTokenAuthenticator"/>
    /// <see cref="SecurityTokenProvider"/>,
    /// <see cref="SecurityTokenResolver"/>
    /// </summary>
    public class ChannelClientCredentials : ClientCredentials
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public ChannelClientCredentials(ClientCredentials clientCredentials)
            : base(clientCredentials)
        {
            // Set SupportInteractive to false to suppress Cardspace UI
            SupportInteractive = false;
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">The <see cref="ChannelClientCredentials"/> to clone.</param>
        protected ChannelClientCredentials(ChannelClientCredentials other)
            : base(other)
        {
        }

        protected override ClientCredentials CloneCore()
        {
            return new ChannelClientCredentials(this);
        }

        /// <summary>
        /// Extensibility point for serving up the <see cref="SecurityTokenManager"/>
        /// </summary>
        /// <returns>the <see cref="SecurityTokenManager"/> passed in the constructor.</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            // return custom security token manager
            return new ChannelClientCredentialsSecurityTokenManager(this);
        }
    }
}
