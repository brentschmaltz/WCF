//------------------------------------------------------------------------------
//     Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;
using RequestSecurityToken = System.IdentityModel.Protocols.WSTrust.RequestSecurityToken;
using RequestSecurityTokenResponse = System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse;

namespace WsTrustClient
{
    public class WSTrustClient : IWSTrustChannelContract
    {
        private WSTrustChannel _channel;
        private object channelLock = new object();

        public WSTrustChannelFactory ChannelFactory
        {
            get;
            protected set;
        }

        public WSTrustChannel Channel
        {
            get
            {
                lock ( channelLock )
                {
                    if ( _channel == null )
                    {
                        _channel = (WSTrustChannel)this.ChannelFactory.CreateChannel();
                    }
                    return _channel;
                }
            }
        }

        public ClientCredentials ClientCredentials
        {
            get
            {
                return ChannelFactory.Credentials;
            }
        }

        public ServiceEndpoint Endpoint
        {
            get
            {
                return ChannelFactory.Endpoint;
            }
        }

        public SecurityTokenHandlerCollectionManager SecurityTokenHandlerCollectionManager
        {
            get
            {
                return ChannelFactory.SecurityTokenHandlerCollectionManager;
            }
        }

        public WSTrustResponseSerializer WSTrustResponseSerializer
        {
            get
            {
                return ChannelFactory.WSTrustResponseSerializer;
            }
            set
            {
                ChannelFactory.WSTrustResponseSerializer = value;
            }
        }

        public WSTrustClient( string endpointConfigurationName, EndpointAddress epa )
            : this( endpointConfigurationName, epa, null, null )
        {
        }

        public WSTrustClient( Binding binding, EndpointAddress epa )
            : this( binding, epa, null, null )
        {
        }

        public WSTrustClient( Binding binding, EndpointAddress epa, TrustVersion trustVersion, ClientCredentials clientCredentials )
            : this( binding, epa, trustVersion, clientCredentials, SecurityTokenHandlerCollectionManager.CreateDefaultSecurityTokenHandlerCollectionManager() )
        {
        }

        public WSTrustClient( string endpointConfigurationName, EndpointAddress epa, TrustVersion trustVersion, ClientCredentials clientCredentials )
            : this( endpointConfigurationName, epa, trustVersion, clientCredentials, SecurityTokenHandlerCollectionManager.CreateDefaultSecurityTokenHandlerCollectionManager() )
        {
        }

        public WSTrustClient( Binding binding,
                              EndpointAddress epa,
                              TrustVersion trustVersion,
                              ClientCredentials clientCredentials,
                              SecurityTokenHandlerCollectionManager securityTokenHandlerCollectionManager )            
        {
            CreateChannelFactory( binding, epa, trustVersion );
            Initialize( clientCredentials, securityTokenHandlerCollectionManager );
        }

        /// <summary>
        /// Constructor for WSTrustClient that can send WS-Trust requests to an STS.
        /// </summary>
        /// <param name="endpointConfigurationName">The name of the endpoint in the application configuration file.</param>
        /// <param name="epa">The address of the service endpoint.</param>
        /// <param name="trustVersion">The version of the WSTrust specification to use for serializing messages.</param>
        /// <param name="clientCredentials">The <see cref="ClientCredentials"/> applying to this session.</param>
        /// <param name="securityTokenHandlerCollectionManager">
        /// The <see cref="SecurityTokenHandlerCollectionManager" /> containing the set of <see cref="SecurityTokenHandler" />
        /// objects used for serializing and validating tokens found in WS-Trust messages.
        /// </param>
        /// <remarks>
        /// If 'trustVersion' is null, default is set to WSTrust 1.3.        
        /// </remarks>
        public WSTrustClient( string endpointConfigurationName,
                              EndpointAddress epa,
                              TrustVersion trustVersion,
                              ClientCredentials clientCredentials,
                              SecurityTokenHandlerCollectionManager securityTokenHandlerCollectionManager )
        {
            CreateChannelFactory( endpointConfigurationName, epa, trustVersion );
            Initialize( clientCredentials, securityTokenHandlerCollectionManager );
        }

        private void CreateChannelFactory( Binding binding, EndpointAddress epa, TrustVersion trustVersion )
        {
            this.ChannelFactory = new WSTrustChannelFactory( binding, epa );
            this.ChannelFactory.TrustVersion = trustVersion;
        }

        private void CreateChannelFactory( string endpointConfigurationName, EndpointAddress epa, TrustVersion trustVersion )
        {
            this.ChannelFactory = new WSTrustChannelFactory( endpointConfigurationName, epa );
            this.ChannelFactory.TrustVersion = trustVersion;
        }

        private void Initialize( ClientCredentials clientCredentials,
                                 SecurityTokenHandlerCollectionManager securityTokenHandlerCollectionManager )
        {
            if ( securityTokenHandlerCollectionManager == null )
            {
                throw new ArgumentNullException( "securityTokenHandlerCollectionManager" );
            }

            this.ChannelFactory.SecurityTokenHandlerCollectionManager = securityTokenHandlerCollectionManager;

            if ( clientCredentials != null )
            {
                this.ChannelFactory.Endpoint.Behaviors.Remove( typeof( ClientCredentials ) );
                this.ChannelFactory.Endpoint.Behaviors.Add( clientCredentials );

                if ( null != clientCredentials.ClientCertificate &&
                    null != clientCredentials.ClientCertificate.Certificate )
                {
                    List<SecurityToken> clientCredentialTokens = new List<SecurityToken>();
                    clientCredentialTokens.Add( new X509SecurityToken( clientCredentials.ClientCertificate.Certificate ) );
                    this.ChannelFactory.SecurityTokenResolver
                        = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( clientCredentialTokens.AsReadOnly(), false );
                }
            }

            //
            // We don't expect any scenarios where a token requestor selects a card to authorize
            // ws-trust messages with an STS.
            //
            this.ClientCredentials.SupportInteractive = false;
        }

        public void Close()
        {
            this.ChannelFactory.Close();
        }

        public RequestSecurityTokenResponse Cancel( RequestSecurityToken request )
        {
            throw new NotSupportedException();
        }

        public IAsyncResult BeginCancel( RequestSecurityToken request, AsyncCallback callback, object state )
        {
            throw new NotSupportedException();
        }

        public void EndCancel( IAsyncResult result, out RequestSecurityTokenResponse response )
        {
            throw new NotSupportedException();
        }

        public SecurityToken Issue( RequestSecurityToken request )
        {
            return this.Channel.Issue( request );
        }

        public SecurityToken Issue( RequestSecurityToken request, out RequestSecurityTokenResponse response )
        {
            return this.Channel.Issue( request, out response );
        }

        public IAsyncResult BeginIssue( RequestSecurityToken request, AsyncCallback callback, object asyncState )
        {
            return this.Channel.BeginIssue( request, callback, asyncState );
        }

        public SecurityToken EndIssue( IAsyncResult result, out RequestSecurityTokenResponse response )
        {
            return this.Channel.EndIssue( result, out response );
        }

        public RequestSecurityTokenResponse Renew( RequestSecurityToken request )
        {
            throw new NotSupportedException();
        }

        public IAsyncResult BeginRenew( RequestSecurityToken request, AsyncCallback callback, object state )
        {
            throw new NotSupportedException();
        }

        public void EndRenew( IAsyncResult result, out RequestSecurityTokenResponse response )
        {
            throw new NotSupportedException();
        }

        public RequestSecurityTokenResponse Validate( RequestSecurityToken request )
        {
            throw new NotSupportedException();
        }

        public IAsyncResult BeginValidate( RequestSecurityToken request, AsyncCallback callback, object state )
        {
            throw new NotImplementedException();
        }

        public void EndValidate( IAsyncResult result, out RequestSecurityTokenResponse response )
        {
            throw new NotSupportedException();
        }

        public Message Cancel( Message message )
        {
            return this.Channel.Cancel( message );
        }

        public IAsyncResult BeginCancel( Message message, AsyncCallback callback, object asyncState )
        {
            return this.Channel.BeginCancel( message, callback, asyncState );
        }

        public Message EndCancel( IAsyncResult asyncResult )
        {
            return this.Channel.EndCancel( asyncResult );
        }

        public Message Issue( Message message )
        {
            return this.Channel.Issue( message );
        }

        public IAsyncResult BeginIssue( Message message, AsyncCallback callback, object asyncState )
        {
            return this.Channel.BeginIssue( message, callback, asyncState );
        }

        public Message EndIssue( IAsyncResult asyncResult )
        {
            return this.Channel.EndIssue( asyncResult );
        }

        public Message Renew( Message message )
        {
            return this.Channel.Renew( message );
        }

        public IAsyncResult BeginRenew( Message message, AsyncCallback callback, object asyncState )
        {
            return this.Channel.BeginRenew( message, callback, asyncState );
        }

        public Message EndRenew( IAsyncResult asyncResult )
        {
            return this.Channel.EndRenew( asyncResult );
        }

        public Message Validate( Message message )
        {
            return this.Channel.Validate( message );
        }

        public IAsyncResult BeginValidate( Message message, AsyncCallback callback, object asyncState )
        {
            return this.Channel.BeginValidate( message, callback, asyncState );
        }

        public Message EndValidate( IAsyncResult asyncResult )
        {
            return this.Channel.EndValidate( asyncResult );
        }
    }
}
