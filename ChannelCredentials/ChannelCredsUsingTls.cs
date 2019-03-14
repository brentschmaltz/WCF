
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;
using System.IO;

namespace IssuedToken
{
    // httpcfg.exe set ssl -i 127.0.0.1:443 -h <thumbprint of cert used> 
    // 97249e1a5fa6bee5e515b82111ef524a4c91583f
    // DO NOT put :0443

    /// <summary>
    /// This code demonstrates how a single ChannelFactory can be used to create channels
    /// that supply different client credentials when establishing an SCT.  In addition
    /// multiple SAML tokens are used to represent the user.  This simulates getting a token
    /// from an STS and augmentating that with claims carried in a locally generated token.
    /// The binding establishes a session over a TLS channel. This results in good performance
    /// as the tokens are transformed into claims once at the server and a SCT is to link back to 
    /// these claims on the server.  Channel protection is manitained by TLS.
    /// </summary>
    public class ChannelCredsUsingTls
    {
        static string serviceAddress = "https://127.0.0.1:443/ChannelCredsUsingTls";
        static string localhostDN = "CN=localhost";
        static string stsDN = "CN=STS";

        public static string LiveIDToken = "LiveIDToken";
        public static string LocalToken = "LocalToken";

        public static string LiveIDTokenIssuer = "LiveIDTokenIssuer";
        public static string LocalTokenIssuer = "LocalTokenIssuer";

        public static string LiveIDAddress = "http://LiveID/Address";
        public static string LocalAddress = "http://Local/Address";

        public static BinarySecretSecurityToken LiveIdProofToken = new MyBinarySecurityToken( 256 );

        public static void Run( string[] args )
        {
            // Callback to validate service cert
            ServicePointManager.ServerCertificateValidationCallback = ValidationCallback.ValidateServerCertificate;

            // Create a tokens that will be attached on to each channel
            SecurityToken stLiveChannel1 = BuildLiveToken();
            SecurityToken stLocalChannel1 = BuildLocalToken();

            SecurityToken stLiveChannel2 = BuildLiveToken();
            SecurityToken stLocalChannel2 = BuildLocalToken();

            // Client <-> Service.
            CustomBinding serviceBinding = GetServiceBinding( );

            // Service
            ServiceHost serviceHost = new ServiceHost( typeof( RequestReply ), new Uri( serviceAddress ) );
            serviceHost.AddServiceEndpoint( typeof( IRequestReply ), serviceBinding, serviceAddress );
            serviceHost.Credentials.ServiceCertificate.SetCertificate( "CN=localhost", StoreLocation.LocalMachine, StoreName.My );

            // These three setting are for convenience when developing and are not secure.
            serviceHost.Credentials.IssuedTokenAuthentication.AudienceUriMode = AudienceUriMode.Never;
            serviceHost.Credentials.IssuedTokenAuthentication.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Credentials.IssuedTokenAuthentication.AllowUntrustedRsaIssuers = true;
           
            // This is only needed if you want to hook custom token authenticators for the local and LiveID tokens.
            serviceHost.Description.Behaviors.Add( new ChannelCredsServiceCredentials( serviceHost.Description.Behaviors.Remove<ServiceCredentials>() ) );
            serviceHost.Open();

            // The subject name of the certificate does not match the end point address need to set epi.
            EndpointAddress epa = new EndpointAddress( new Uri( serviceAddress ), EndpointIdentity.CreateDnsIdentity( "localhost"), new AddressHeaderCollection() );

            // Client
            CustomBinding clientBinding = GetClientBinding();
            SetMaxTimeout( clientBinding );
            ChannelFactory<IRequestReply> cf = new ChannelFactory<IRequestReply>( clientBinding, epa );

            // hook custom token provider
            cf.Endpoint.Behaviors.Add( new ChannelCredsClientCredentials( cf.Endpoint.Behaviors.Remove<ClientCredentials>() ) );


            // For debugging purposes
            SetMaxTimeout( serviceBinding );            
            DisplayBindingInfoToConsole( serviceHost );
            
            IRequestReply rr1 = cf.CreateChannel();
            ( (IChannel)rr1 ).GetProperty<ChannelParameterCollection>().Add( new ChannelCreds( "1", stLiveChannel1, stLocalChannel1 ) );

            IRequestReply rr2 = cf.CreateChannel();
            ( (IChannel)rr2 ).GetProperty<ChannelParameterCollection>().Add( new ChannelCreds( "2", stLiveChannel2, stLocalChannel2 ) );

            try
            {
                Console.WriteLine( rr1.SendString( "IssuedTokenForSsl - sr1 - Hello" ) );
            }
            catch ( Exception e )
            {
                Console.WriteLine( "Caught Exception => '{0}'", e.ToString() );
            }
        }

        /// <summary>
        /// the comments in GetServiceBinding (below) apply here. Different TokenTypes could be passed in IssuedSecurityTokenParameters which is
        /// another way of distinguishing which token should be returned in SecurityTokenProvider.GetTokenCore().
        /// </summary>
        /// <returns></returns>
        static CustomBinding GetClientBinding()
        {
            // the address passed in the EndpointAddress allows the STP to determine which token to add.
            // We could use custom token types as well.

            IssuedSecurityTokenParameters istpLiveToken = new IssuedSecurityTokenParameters( SecurityTokenTypes.Saml, new EndpointAddress( LiveIDAddress ), new WSHttpBinding() );
            IssuedSecurityTokenParameters istpLocalToken = new IssuedSecurityTokenParameters( SecurityTokenTypes.Saml, new EndpointAddress( LocalAddress ), new WSHttpBinding() );

            TransportSecurityBindingElement tsbe = new TransportSecurityBindingElement();
            tsbe.OptionalEndpointSupportingTokenParameters.SignedEndorsing.Add( istpLiveToken );
            tsbe.OptionalEndpointSupportingTokenParameters.SignedEndorsing.Add( istpLocalToken );

            SecurityBindingElement ssbe = SecurityBindingElement.CreateSecureConversationBindingElement( tsbe );
            TextMessageEncodingBindingElement txbe = new TextMessageEncodingBindingElement();
            HttpsTransportBindingElement tbe = new HttpsTransportBindingElement();

            CustomBinding cb = new CustomBinding( ssbe, txbe, tbe );

            return cb;
        }

        // WCF will not allow adding IssuedSecurityTokenParameters that resolve to the same SecurityTokenAuthenticator type.
        // If the client sends two tokens of the same type, WCF will process them with a single STA.
        // If it is necessary to have custom handling of the multiple tokens, then there will need to be a way to distinguish them is
        // they are both SAML. If there is no way to distinguish them, then custom tokens will be needed and the Serializer will need to be 
        // extended.
        static CustomBinding GetServiceBinding()
        {
            IssuedSecurityTokenParameters samlToken = new IssuedSecurityTokenParameters( SecurityTokenTypes.Saml, new EndpointAddress( "http://SAMLToken/NotUsed" ), new WSHttpBinding() );

            // this is how you would specify the custom token types which would trigger custom STA's to be used see: ChannelCredsServiceCredentialsSecurityTokenManager.CreateSecurityTokenAuthenticator
            // IssuedSecurityTokenParameters istpLiveToken = new IssuedSecurityTokenParameters( ChannelCredsUsingTls.LiveIDToken, new EndpointAddress( "http://LiveId/NotUsed" ), new WSHttpBinding() );
            // IssuedSecurityTokenParameters istpLocalToken = new IssuedSecurityTokenParameters( ChannelCredsUsingTls.LocalToken, new EndpointAddress( "http://Local/NotUsed" ), new WSHttpBinding() );

            TransportSecurityBindingElement tsbe = new TransportSecurityBindingElement();
            tsbe.OptionalEndpointSupportingTokenParameters.SignedEndorsing.Add( samlToken );

            // if using custom STA's, use this logic
            //tsbe.EndpointSupportingTokenParameters.SignedEndorsing.Add( istpLiveToken );
            //tsbe.EndpointSupportingTokenParameters.SignedEndorsing.Add( istpLocalToken );

            SecurityBindingElement ssbe = SecurityBindingElement.CreateSecureConversationBindingElement( tsbe );
            TextMessageEncodingBindingElement txbe = new TextMessageEncodingBindingElement();
            HttpsTransportBindingElement tbe = new HttpsTransportBindingElement();

            CustomBinding cb = new CustomBinding( ssbe, txbe, tbe );

            return cb;
        }

        public static SigningCredentials GetSigningCreds<T>( BinarySecretSecurityToken issuerToken ) where T : SecurityKeyIdentifierClause
        {
            // Thumbprint requires WSSE 1.1, 1.0 does not support thumbprint.
            T skic = issuerToken.CreateKeyIdentifierClause<T>();
            SecurityKeyIdentifier ski = new SecurityKeyIdentifier( skic );

            // used to sign token
            return new SigningCredentials( issuerToken.SecurityKeys[0],
                                           SecurityAlgorithms.HmacSha1Signature,
                                           SecurityAlgorithms.Sha1Digest,
                                           ski );

        }

        public static SigningCredentials GetSigningCreds<T>( X509SecurityToken issuerToken ) where T : SecurityKeyIdentifierClause
        {
            // Thumbprint requires WSSE 1.1, 1.0 does not support thumbprint.
            T skic = issuerToken.CreateKeyIdentifierClause<T>();
            SecurityKeyIdentifier ski = new SecurityKeyIdentifier( skic );

            // used to sign token
            return new SigningCredentials( issuerToken.SecurityKeys[0],
                                           SecurityAlgorithms.RsaSha1Signature,
                                           SecurityAlgorithms.Sha1Digest,
                                           ski );

        }

        public static X509SecurityToken GetLocalX509Token()
        {
            return new X509SecurityToken( Util.GetCertFromMyLocalmachine( localhostDN ) );
        }

        public static X509SecurityToken GetLiveX509Token()
        {
            return new X509SecurityToken( Util.GetCertFromMyLocalmachine( stsDN ) );
        }

        /// <summary>
        /// Simulates building the inner 'LiveID' token.
        /// </summary>
        /// <returns></returns>
        public static SecurityToken BuildLiveToken()
        {
            SamlConditions sc = new SamlConditions();

            // Populate attributes
            List<SamlAttribute> attributes = new List<SamlAttribute>();
            List<string> attributesValues = new List<string>();
            
            attributesValues.Add( "client11@emailaddress" );
            attributes.Add( new SamlAttribute( "http://schemas.microsoft.com/exchange/xrop/2010", "PrimarySMTPEmailAddress", attributesValues ) );

            attributesValues.Clear();

            attributesValues.Add( "Owner" );
            attributes.Add( new SamlAttribute( "http://schemas.microsoft.com/exchange/xrop/2010", "Role", attributesValues ) );

            
            SamlSecurityToken st = SamlTokenBuilder.CreateSamlToken(
                                                LiveIDTokenIssuer,
                                                ChannelCredsUsingTls.LiveIdProofToken,
                                                GetSigningCreds< X509RawDataKeyIdentifierClause>( GetLiveX509Token() ),
                                                null,
                                                sc,
                                                attributes );
            return st;

        }

        /// <summary>
        /// Simulates building the inner 'Local' token that aguments claims returned from Live.
        /// </summary>
        /// <returns></returns>
        public static SecurityToken BuildLocalToken()
        {
            SamlConditions sc = new SamlConditions();

            // Populate attributes
            List<SamlAttribute> attributes = new List<SamlAttribute>();
            List<string> attributesValues = new List<string>();

            // Populate 'additional' local attribute
            attributesValues.Add( "Bob" );
            attributes.Add( new SamlAttribute( "http://schemas.microsoft.com/exchange/xrop/2010", "LocalName", attributesValues ) );


            SamlSecurityToken st = SamlTokenBuilder.CreateSamlToken(
                                                LocalTokenIssuer,
                                                ChannelCredsUsingTls.LiveIdProofToken,
                                                GetSigningCreds<BinarySecretKeyIdentifierClause>( ChannelCredsUsingTls.LiveIdProofToken ),
                                                null,
                                                sc,
                                                attributes );
            return st;

        }

        #region Debug Utilities
        public static void SetMaxTimeout( System.ServiceModel.Channels.Binding binding, TimeSpan timeSpan )
        {
            binding.CloseTimeout = timeSpan;
            binding.OpenTimeout = timeSpan;
            binding.ReceiveTimeout = timeSpan;
            binding.SendTimeout = timeSpan;
        }

        public static void SetMaxTimeout( System.ServiceModel.Channels.Binding binding )
        {
            SetMaxTimeout( binding, TimeSpan.MaxValue );
        }

        public static void DisplayBindingInfoToConsole( ServiceHost serviceHost )
        {

            for ( int i = 0; i < serviceHost.ChannelDispatchers.Count; i++ )
            {
                ChannelDispatcher channelDispatcher = serviceHost.ChannelDispatchers[i] as ChannelDispatcher;
                if ( channelDispatcher != null )
                {
                    for ( int j = 0; j < channelDispatcher.Endpoints.Count; j++ )
                    {
                        EndpointDispatcher endpointDispatcher = channelDispatcher.Endpoints[j];
                        Console.WriteLine( "Listening on " + endpointDispatcher.EndpointAddress + "..." );
                    }
                }
            }
        }
        #endregion
    }

    class ChannelCredsServiceCredentials : ServiceCredentials
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public ChannelCredsServiceCredentials( ServiceCredentials cc )
            : base( cc )
        {}

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">The SamlClientCredentials to create a copy of</param>
        protected ChannelCredsServiceCredentials( ChannelCredsServiceCredentials other )
            : base( other )
        {
        }

        protected override ServiceCredentials CloneCore()
        {
            return new ChannelCredsServiceCredentials( this );
        }

        /// <summary>
        /// Extensibility point for serving up the WSTrustChannelClientSecurityTokenManager
        /// </summary>
        /// <returns>LiveIdClientSecurityTokenManager</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            // return custom security token manager
            return new ChannelCredsServiceCredentialsSecurityTokenManager( this );
        }
    }

    /// <summary>
    /// These client credentials class that will serve up a SecurityTokenManager that 
    /// can obtains tokens from ChannelParameters
    /// </summary>
    class ChannelCredsClientCredentials : ClientCredentials
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public ChannelCredsClientCredentials( ClientCredentials cc )
            : base( cc )
        {
            // Set SupportInteractive to false to suppress Cardspace UI
            SupportInteractive = false;
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">The SamlClientCredentials to create a copy of</param>
        protected ChannelCredsClientCredentials( ChannelCredsClientCredentials other )
            : base( other )
        {
        }

        protected override ClientCredentials CloneCore()
        {
            return new ChannelCredsClientCredentials( this );
        }

        /// <summary>
        /// Extensibility point for serving up the WSTrustChannelClientSecurityTokenManager
        /// </summary>
        /// <returns>LiveIdClientSecurityTokenManager</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            // return custom security token manager
            return new ChannelCredsClientCredentialsSecurityTokenManager( this );
        }
    }

    /// <summary>
    /// Returns a WSTrustChannelSecurityTokenProvider to obtain token Saml
    /// </summary>
    class ChannelCredsClientCredentialsSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        public ChannelCredsClientCredentialsSecurityTokenManager( ChannelCredsClientCredentials clientCredentials )
            : base( clientCredentials )
        { }

        /// <summary>
        /// Make use of this extensibility point for returning a custom SecurityTokenProvider when SAML tokens are specified in the tokenRequirement
        /// Two methods are shown here to distinguish which token to use, depends on what is specified in GetClientBinding.
        /// In both cases just return a simple STP that holds the token. It will be called when the channel needs the token.
        /// </summary>
        /// <param name="tokenRequirement">A SecurityTokenRequirement  </param>
        /// <returns>The appropriate SecurityTokenProvider</returns>
        public override SecurityTokenProvider CreateSecurityTokenProvider( SecurityTokenRequirement tokenRequirement )
        {
            SecurityTokenProvider stp = null;

            if ( tokenRequirement.TokenType == ChannelCredsUsingTls.LiveIDToken )
            {
                ChannelCreds channelParams = FindChannelParams( tokenRequirement );
                stp = new SimpleSecurityTokenProvider( channelParams.LiveIdToken );
            }
            else if ( tokenRequirement.TokenType == ChannelCredsUsingTls.LocalToken )
            {
                ChannelCreds channelParams = FindChannelParams( tokenRequirement );
                stp = new SimpleSecurityTokenProvider( channelParams.LocalToken );
            }
            else if ( tokenRequirement.TokenType == SecurityTokenTypes.Saml )
            {
                ChannelCreds channelParams = FindChannelParams( tokenRequirement );

                EndpointAddress issuerAddress = null;
                if ( tokenRequirement.TryGetProperty<EndpointAddress>( ServiceModelSecurityTokenRequirement.IssuerAddressProperty, out issuerAddress ) )
                {
                    if ( issuerAddress.Uri.AbsoluteUri.Equals( ChannelCredsUsingTls.LiveIDAddress, StringComparison.OrdinalIgnoreCase ) )
                        stp = new SimpleSecurityTokenProvider( channelParams.LiveIdToken );
                    else if ( issuerAddress.Uri.AbsoluteUri.Equals( ChannelCredsUsingTls.LocalAddress, StringComparison.OrdinalIgnoreCase ) )
                        stp = new SimpleSecurityTokenProvider( channelParams.LocalToken );
                    else
                        throw new InvalidProgramException( "issuerAddress is not known" );
                }
                else
                {
                    throw new InvalidProgramException( " need to have issuer address " );
                }
            }
            else
            {
                stp = base.CreateSecurityTokenProvider( tokenRequirement );
            }

            return stp;
        }

        /// <summary>
        /// Looks for the first FederatedClientCredentialsParameters object in the ChannelParameterCollection
        /// property on the tokenRequirement.
        /// </summary>
        internal static ChannelCreds FindChannelParams( SecurityTokenRequirement tokenRequirement )
        {
            ChannelCreds channelParams = null;

            ChannelParameterCollection channelParameterCollection = null;
            if ( tokenRequirement.TryGetProperty<ChannelParameterCollection>(
                                     ServiceModelSecurityTokenRequirement.ChannelParametersCollectionProperty,
                                     out channelParameterCollection ) )
            {
                if ( channelParameterCollection != null )
                {
                    foreach ( object obj in channelParameterCollection )
                    {
                        channelParams = obj as ChannelCreds;
                        if ( channelParams != null )
                        {
                            break;
                        }
                    }
                }
            }

            return channelParams;
        }
    }

    class ChannelCredsServiceCredentialsSecurityTokenManager : ServiceCredentialsSecurityTokenManager
    {
        public ChannelCredsServiceCredentialsSecurityTokenManager( ServiceCredentials sc )
            : base( sc )
        { }

        public override SecurityTokenAuthenticator CreateSecurityTokenAuthenticator( SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver )
        {
            if ( tokenRequirement == null )
                throw new ArgumentNullException( "tokenRequirement" );

            SecurityTokenAuthenticator sta;

            // The if statements here corespond to the Endpoint tokens using the IssuedTokenParameters in: GetServiceBinding.
            // The advantage of using a custom STA is if you need tight control over processing the different tokens.
            //
            // If the SecurityKeyIdentifierClause used to for the signing key on the SamlToken is not X509RawDataKeyIdentifierClause
            // you will need to add the tokens to the outOfBandTokenResolver.
            //
            // Add this code:
            // List<SecurityToken> tokens = new List<SecurityToken>();
            // tokens.Add( ChannelCredsUsingTls.GetLiveX509Token() );
            // outOfBandTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true );

            if ( tokenRequirement.TokenType == ChannelCredsUsingTls.LiveIDToken )
            {
                List<SecurityToken> tokens = new List<SecurityToken>();
                outOfBandTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true );

                List<SecurityTokenAuthenticator> authenticators = new List<SecurityTokenAuthenticator>();               
                sta = new LiveIDSamlSecurityTokenAuthenticator( authenticators, TimeSpan.FromMinutes( 5 ) );
            }
            else if ( tokenRequirement.TokenType == ChannelCredsUsingTls.LocalToken )
            {
                List<SecurityToken> tokens = new List<SecurityToken>();
                outOfBandTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true );

                List<SecurityTokenAuthenticator> authenticators = new List<SecurityTokenAuthenticator>();
                sta = new LocalSamlSecurityTokenAuthenticator( authenticators, TimeSpan.FromMinutes(5) );
            }
            else 
            {


                if ( tokenRequirement.TokenType == SecurityTokenTypes.Saml )
                {
                    List<SecurityToken> tokens = new List<SecurityToken>();
                    tokens.Add( ChannelCredsUsingTls.LiveIdProofToken );
                    outOfBandTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true );

                    List<SecurityTokenAuthenticator> authenticators = new List<SecurityTokenAuthenticator>();
                    authenticators.Add( new BinarySecurityTokenAuthenticator() );
                    authenticators.Add( new X509SecurityTokenAuthenticator(X509CertificateValidator.None) );
                    sta = new SamlSecurityTokenAuthenticator( authenticators, TimeSpan.FromMinutes( 5 ) );
                }
                else
                {
                    sta = base.CreateSecurityTokenAuthenticator( tokenRequirement, out outOfBandTokenResolver );
                }

                // need aggregate resolver that can resolve binary keys.
            }
            return sta;
        }
    }

    /// <summary>
    /// Returns the SecurityToken that was passed in the constructor
    /// </summary>
    class SimpleSecurityTokenProvider : SecurityTokenProvider
    {
        SecurityToken _st;

        public SimpleSecurityTokenProvider( SecurityToken st )
        {
            if ( st == null )
                throw new ArgumentNullException( "st" );

            _st = st;
        }

        /// <summary>
        /// Just return token
        /// </summary>
        protected override SecurityToken GetTokenCore( TimeSpan timeout )
        {
            return _st;
        }
    }

    class LiveIDSamlSecurityTokenAuthenticator : SamlSecurityTokenAuthenticator
    {
        public LiveIDSamlSecurityTokenAuthenticator( IList<SecurityTokenAuthenticator> authenticators, TimeSpan clockSkew )
            : base( authenticators, clockSkew )
        { }

        // Because saml tokens are used, the base will return true and WCF runtime will 
        // record that this authenticator was used twice and the will other authenticator will not be 
        // recorded as used, the accounting will be off and the security header processing will fail.
        // So there is a need to distinguish the tokens somehow. If this is fragile, then custom token types 
        // could be used, this would require adding a custom serializer that knows how work with the custom token.
        protected override bool CanValidateTokenCore( SecurityToken token )
        {
            SamlSecurityToken sst = token as SamlSecurityToken;
            if ( sst != null )
            {
                return ( sst.Assertion.Issuer == ChannelCredsUsingTls.LiveIDTokenIssuer );
            }

            return false;
        }
    }

    class LocalSamlSecurityTokenAuthenticator : SamlSecurityTokenAuthenticator
    {
        public LocalSamlSecurityTokenAuthenticator( IList<SecurityTokenAuthenticator> authenticators, TimeSpan clockSkew )
            : base( authenticators, clockSkew )
        { }

        // See comment above in LiveIDSamlSecurityTokenAuthenticator.CanValidateTokenCore
        protected override bool CanValidateTokenCore( SecurityToken token )
        {
            SamlSecurityToken sst = token as SamlSecurityToken;
            if ( sst != null )
            {
                return ( sst.Assertion.Issuer == ChannelCredsUsingTls.LocalTokenIssuer );
            }

            return false;
        }
    }

    class BinarySecurityTokenAuthenticator : SecurityTokenAuthenticator
    {
        protected override bool CanValidateTokenCore( SecurityToken token )
        {
            if ( token is BinarySecretSecurityToken )
                return true;

            return false;
        }

        protected override ReadOnlyCollection<IAuthorizationPolicy> ValidateTokenCore( SecurityToken token )
        {
            List<IAuthorizationPolicy> policies = new List<IAuthorizationPolicy>();
            return policies.AsReadOnly();
        }
    }

    public class ChannelCreds
    {
        string _id;
        SecurityToken _stLive;
        SecurityToken _stLocal;

        public ChannelCreds( string id, SecurityToken stLive, SecurityToken stLocal )
        {
            if ( id == null )
                throw new ArgumentNullException( "id" );

            if ( stLive == null )
                throw new ArgumentNullException( "stLive" );

            if ( stLocal == null )
                throw new ArgumentNullException( "stLocal" );

            _id = id;
            _stLive = stLive;
            _stLocal = stLocal;

        }

        /// <summary>
        /// gets the MapiID for cahnnel
        /// </summary>
        public string Id
        {
            get { return _id; }
        }

        /// <summary>
        /// Gets SecurityToken that came from live
        /// </summary>
        public SecurityToken LiveIdToken
        {
            get { return _stLive; }
        }

        /// <summary>
        /// Gets SecurityToken that was created locally
        /// </summary>
        public SecurityToken LocalToken
        {
            get { return _stLocal; }
        }

    }

    public class Util
    {
        public static X509Certificate2 GetCertFromMyLocalmachine( string subjectDistinguishedName )
        {
            StoreName storeName = StoreName.My;
            StoreLocation storeLocation = StoreLocation.LocalMachine;
            X509Store store = null;
            try
            {
                store = new X509Store( storeName, storeLocation );
                store.Open( OpenFlags.ReadOnly );
                X509Certificate2Collection certs = store.Certificates.Find( X509FindType.FindBySubjectDistinguishedName,
                                                                           subjectDistinguishedName, false );
                if ( certs.Count != 1 )
                {
                    throw new Exception( "FedUtil: Certificate not found or more than one certificate found" );
                }
                return (X509Certificate2)certs[0];
            }
            finally
            {
                if ( store != null ) store.Close();
            }
        }
    }

    public class SamlTokenBuilder
    {
        /// <summary>
        /// Creates a SAML Token with the input parameters
        /// </summary>
        /// <param name="stsName">Name of the STS issuing the SAML Token</param>
        /// <param name="proofToken">Associated Proof Token will end up in SubjectConfirmation. Can be null, if so, Sender-Vouches will be in SubjectConfirmation </param>
        /// <param name="signingCredentials">Will be used to sign token</param>
        /// <param name="proofKeyEncryptionToken">Token to encrypt the proof key with</param>
        /// <param name="samlConditions">The Saml Conditions to be used in the construction of the SAML Token</param>
        /// <param name="samlAttributes">The Saml Attributes to be used in the construction of the SAML Token</param>
        /// <returns>A SAML Token</returns>
        public static SamlSecurityToken CreateSamlToken( string stsName,
                                                        BinarySecretSecurityToken proofToken,
                                                        SigningCredentials signingCredentials,
                                                        SecurityToken proofKeyEncryptionToken,
                                                        SamlConditions samlConditions,
                                                        IEnumerable<SamlAttribute> samlAttributes )
        {
            // is holder of key or bearer
            string confirmationType;

            // represents the user if a proofToken is available
            SecurityKeyIdentifier ski = null;

            if ( proofToken != null )
            {
                confirmationType = SamlConstants.HolderOfKey;
                // the key clause that is for the user


                if ( proofKeyEncryptionToken != null )
                {
                    byte[] wrappedKey = proofKeyEncryptionToken.SecurityKeys[0].EncryptKey( SecurityAlgorithms.RsaOaepKeyWrap, proofToken.GetKeyBytes() );
                    SecurityKeyIdentifierClause encryptingTokenClause = proofKeyEncryptionToken.CreateKeyIdentifierClause<X509ThumbprintKeyIdentifierClause>();
                    EncryptedKeyIdentifierClause encryptedKeyClause = new EncryptedKeyIdentifierClause( wrappedKey, SecurityAlgorithms.RsaOaepKeyWrap, new SecurityKeyIdentifier( encryptingTokenClause ) );
                    ski = new SecurityKeyIdentifier( encryptedKeyClause );
                }
                else
                {
                    ski = new SecurityKeyIdentifier( new BinarySecretKeyIdentifierClause( proofToken.GetKeyBytes() ) );
                }

            }
            else
            {
                confirmationType = SamlConstants.SenderVouches;
            }

            List<string> confirmationMethods = new List<string>( 1 );
            confirmationMethods.Add( confirmationType );

            SamlSubject samlSubject = new SamlSubject( null,
                                                      null,
                                                      null,
                                                      confirmationMethods,
                                                      null,
                                                      ski );

            // to use this token to sign we need to attach the proof token
            if ( proofToken != null && proofToken.SecurityKeys != null && proofToken.SecurityKeys[0] != null )
            {
                samlSubject.Crypto = proofToken.SecurityKeys[0];
            }

            List<SamlStatement> samlSubjectStatements = new List<SamlStatement>();
            SamlAttributeStatement samlAttributeStatement = new SamlAttributeStatement( samlSubject, samlAttributes );
            samlSubjectStatements.Add( samlAttributeStatement );

            String id = "_" + Guid.NewGuid().ToString();
            SamlAssertion samlAssertion = new SamlAssertion( id,
                                                            stsName,
                                                            DateTime.UtcNow,
                                                            samlConditions,
                                                            new SamlAdvice(),
                                                            samlSubjectStatements
                                                            );
            samlAssertion.SigningCredentials = signingCredentials;

            return new SamlSecurityToken( samlAssertion );
        }


        public static string SignAndStreamSamlToken( SamlSecurityToken token )
        {
            MemoryStream ms = new MemoryStream();
            SecurityTokenSerializer serializer = WSSecurityTokenSerializer.DefaultInstance;

            XmlWriter writer = XmlWriter.Create( ms );
            serializer.WriteToken( writer, token );
            writer.Close();

            string tokenAsString = Encoding.UTF8.GetString( ms.ToArray() );

            return tokenAsString;
        }
    }

    public class MyBinarySecurityToken : BinarySecretSecurityToken
    {
        public MyBinarySecurityToken( int keysize )
            : base( keysize )
        {

        }

        public override bool MatchesKeyIdentifierClause( SecurityKeyIdentifierClause keyIdentifierClause )
        {
            BinarySecretKeyIdentifierClause clause = keyIdentifierClause as BinarySecretKeyIdentifierClause;
            if ( clause != null )
                return clause.Matches( GetKeyBytes() );

            return false;
        }

        public override bool CanCreateKeyIdentifierClause<T>()
        {
            return ((typeof(T) == typeof(BinarySecretKeyIdentifierClause)));
        }

        public override T CreateKeyIdentifierClause<T>()
        {
            if ((typeof(T) == typeof(BinarySecretKeyIdentifierClause)) )
                return new BinarySecretKeyIdentifierClause( GetKeyBytes(), true) as T;

            throw new NotSupportedException("Don't know about clause type");
        }
    }
}
