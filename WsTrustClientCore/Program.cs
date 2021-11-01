using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Federation;
using System.ServiceModel.Security;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsTrust;
using WcfContracts;

namespace WsTrustClientCore
{
    class Program
    {
        static AppliesTo AppliesTo => new AppliesTo(new EndpointReference("https://127.0.0.1:443/STS"));
        const string _usernameMixedEndpointTrust13 = @"https://127.0.0.1:5443/trust/13/usernamemixed";
        const string _windowsTransportEndpointTrust13 = @"https://127.0.0.1:5443/trust/13/windowsTransport";
        const string _windowsTransportEndpointTrust2005 = @"https://127.0.0.1:5443/trust/2005/windowsTransport";
        const string _username = @"bob";
        const string _password = @"password";
        const string _saml11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        const string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

        static void Main(string[] args)
        {
            IssueAsyncWithIntegratedWindowsAuthOverTransport(WsTrustVersion.TrustFeb2005, _saml11);
            //IssueAsyncWithIntegratedWindowsAuthOverTransport(WsTrustVersion.TrustFeb2005, _saml20);
            IssueAsyncWithIntegratedWindowsAuthOverTransport(WsTrustVersion.Trust13, _saml11);
            //IssueAsyncWithIntegratedWindowsAuthOverTransport(WsTrustVersion.Trust13, _saml20);
            IssueAsyncWithUserNamePasswordMixedModeAsync(WsTrustVersion.TrustFeb2005, _saml11);
            //IssueAsyncWithUserNamePasswordMixedModeAsync(WsTrustVersion.Trust13, _saml20);
            CancelAsync(WsTrustVersion.TrustFeb2005, _saml11);
            //CancelAsync(WsTrustVersion.TrustFeb2005, _saml20);
            //CancelAsync(WsTrustVersion.Trust13, _saml11);
            //CancelAsync(WsTrustVersion.Trust13, _saml20);
            //IssueMessageAsync(WsTrustVersion.TrustFeb2005, _saml11);
            //IssueMessageAsync(WsTrustVersion.TrustFeb2005, _saml20);
            //IssueMessageAsync(WsTrustVersion.Trust13, _saml11);
            //IssueMessageAsync(WsTrustVersion.Trust13, _saml20);
            //RenewAsync(WsTrustVersion.TrustFeb2005, _saml11);
            //RenewAsync(WsTrustVersion.TrustFeb2005, _saml20);
            //RenewAsync(WsTrustVersion.Trust13, _saml11);
            RenewAsync(WsTrustVersion.Trust13, _saml20);
            //ValidateAsync(WsTrustVersion.TrustFeb2005, _saml11);
            //ValidateAsync(WsTrustVersion.TrustFeb2005, _saml20);
            ValidateAsync(WsTrustVersion.Trust13, _saml11);
            //ValidateAsync(WsTrustVersion.Trust13, _saml20);

            Console.WriteLine($"Press a key to close.");
            Console.ReadKey();
        }

        private static SecurityToken IssueAsyncWithIntegratedWindowsAuthOverTransport(WsTrustVersion trustVersion, string tokenType)
        {
            Console.WriteLine($"IssueAsyncWithIntegratedWindowsAuthOverTransport. WsTrustVersion: '{trustVersion}', TokenType: '{tokenType}'.");

            string trustRequest;
            EndpointAddress endpointAddress;
            if (trustVersion.Equals(WsTrustVersion.Trust13))
            {
                trustRequest = WsTrustActions.Trust13.Issue;
                endpointAddress = new(_windowsTransportEndpointTrust13);
            }
            else
            {
                trustRequest = WsTrustActions.TrustFeb2005.Issue;
                endpointAddress = new(_windowsTransportEndpointTrust2005);
            }

            WS2007HttpBinding binding = new(SecurityMode.Transport);
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Windows;
            WSTrustChannelFactory trustChannelFactory = CreateWSTrustChannelFactory(binding, endpointAddress);
            WSTrustChannel trustChannel = (WSTrustChannel)trustChannelFactory.CreateChannel(endpointAddress);

            return trustChannel.IssueAsync(new WsTrustRequest(trustRequest)
            {
                AppliesTo = AppliesTo,
                TokenType = tokenType,
                WsTrustVersion = trustVersion
            }).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        private static SecurityToken IssueAsyncWithUserNamePasswordMixedModeAsync(WsTrustVersion trustVersion, string tokenType)
        {
            Console.WriteLine($"IssueAsyncWithUserNamePasswordMixedModeAsync. WsTrustVersion: '{trustVersion}', TokenType: '{tokenType}'.");

            WS2007HttpBinding binding = new(SecurityMode.TransportWithMessageCredential);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            EndpointAddress endpointAddress = new(_usernameMixedEndpointTrust13);

            WSTrustChannelFactory trustChannelFactory = CreateWSTrustChannelFactory(binding, endpointAddress);
            trustChannelFactory.Credentials.UserName.UserName = _username;
            trustChannelFactory.Credentials.UserName.Password = _password;

            WSTrustChannel trustChannel = (WSTrustChannel)trustChannelFactory.CreateChannel(endpointAddress);
            string trustRequest = (trustVersion.Equals(WsTrustVersion.Trust13)) ? WsTrustActions.Trust13.Issue : WsTrustActions.TrustFeb2005.Issue;
            try
            {
                SecurityToken token = trustChannel.IssueAsync(new WsTrustRequest(trustRequest)
                {
                    AppliesTo = AppliesTo,
                    TokenType = tokenType,
                    WsTrustVersion = trustVersion
                }).ConfigureAwait(false).GetAwaiter().GetResult();

                Console.WriteLine($"SecurityToken: {token}");

                return token;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception thrown: '{ex}'.");
            }

            return null;
        }

        #region Using Message
        private static Message CancelAsync(WsTrustVersion trustVersion, string tokenType)
        {
            try
            {
                Console.WriteLine($"Cancel. TrustVersion: '{trustVersion}', TokenType: '{tokenType}'.");
                string trustRequest = (trustVersion.Equals(WsTrustVersion.Trust13)) ? WsTrustActions.Trust13.Cancel : WsTrustActions.TrustFeb2005.Cancel;
                Message message = CreateRequest(new WsTrustRequest(trustRequest)
                {
                    AppliesTo = AppliesTo,
                    TokenType = tokenType,
                    WsTrustVersion = trustVersion
                });

                Message result = CreateWSTrustChannel().CancelAsync(message).ConfigureAwait(false).GetAwaiter().GetResult();
                Console.WriteLine($"Return Message: '{result}'.");
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception thrown: '{ex}");
            }

            return null;
        }

        private static Message IssueMessageAsync(WsTrustVersion trustVersion, string tokenType)
        {
            try
            {
                Console.WriteLine($"Issue. TrustVersion: '{trustVersion}', TokenType: '{tokenType}'.");
                string trustRequest = (trustVersion.Equals(WsTrustVersion.Trust13)) ? WsTrustActions.Trust13.Issue : WsTrustActions.TrustFeb2005.Issue;
                Message message = CreateRequest(new WsTrustRequest(trustRequest)
                {
                    AppliesTo = AppliesTo,
                    TokenType = tokenType,
                    WsTrustVersion = trustVersion
                });

                Message result = CreateWSTrustChannel().IssueAsync(message).ConfigureAwait(false).GetAwaiter().GetResult();
                Console.WriteLine($"Return Message: '{result}'.");
                return result;
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Exception thrown: '{ex}");
            }

            return null;
        }

        private static Message RenewAsync(WsTrustVersion trustVersion, string tokenType)
        {
            try
            { 
                Console.WriteLine($"Renew. TrustVersion: '{trustVersion}', TokenType: '{tokenType}'.");
                string trustRequest = (trustVersion.Equals(WsTrustVersion.Trust13)) ? WsTrustActions.Trust13.Renew : WsTrustActions.TrustFeb2005.Renew;
                Message message = CreateRequest(new WsTrustRequest(trustRequest)
                {
                    AppliesTo = AppliesTo,
                    TokenType = tokenType,
                    WsTrustVersion = trustVersion
                });

                Message result = CreateWSTrustChannel().RenewAsync(message).ConfigureAwait(false).GetAwaiter().GetResult();
                Console.WriteLine($"Return Message: '{result}'.");
                return result;
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Exception thrown: '{ex}");
            }

            return null;
        }

        private static Message ValidateAsync(WsTrustVersion trustVersion, string tokenType)
        {
            Console.WriteLine($"Validate. TrustVersion: '{trustVersion}', TokenType: '{tokenType}'.");
            string trustRequest = (trustVersion.Equals(WsTrustVersion.Trust13)) ? WsTrustActions.Trust13.Validate : WsTrustActions.TrustFeb2005.Validate;
            try
            {
                Message message = CreateRequest(new WsTrustRequest(trustRequest)
                {
                    AppliesTo = AppliesTo,
                    TokenType = tokenType,
                    WsTrustVersion = trustVersion
                });

                Message result = CreateWSTrustChannel().ValidateAsync(message).ConfigureAwait(false).GetAwaiter().GetResult();
                Console.WriteLine($"Return Message: '{result}'.");
                return result;
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Exception thrown: '{ex}");
            }

            return null;
        }
        #endregion

        private static WSTrustChannelFactory CreateWSTrustChannelFactory(Binding binding, EndpointAddress endpointAddress)
        {
            // TODO - why does both the WSTrustChannelFactory ctor and CreatChannel take an EndpointAddress
            // TODO - why does both the WSTrustChannelFactory and WsTrustRequest have the WsTrustVersion
            WSTrustChannelFactory trustChannelFactory = new WSTrustChannelFactory(binding, endpointAddress)
            {
                TrustVersion = WsTrustVersion.Trust13,
            };

            trustChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication { CertificateValidationMode = X509CertificateValidationMode.None };
            return trustChannelFactory;
        }

        private static WSTrustChannel CreateWSTrustChannel()
        {
            WS2007HttpBinding binding = new(SecurityMode.TransportWithMessageCredential);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            EndpointAddress endpointAddress = new(_usernameMixedEndpointTrust13);

            WSTrustChannelFactory trustChannelFactory = CreateWSTrustChannelFactory(binding, endpointAddress);
            trustChannelFactory.Credentials.UserName.UserName = _username;
            trustChannelFactory.Credentials.UserName.Password = _password;

            return (WSTrustChannel)trustChannelFactory.CreateChannel(endpointAddress);
        }

        /// <summary>
        /// Creates a <see cref="Message"/> object that represents a WS-Trust RST message.
        /// </summary>
        /// <param name="trustRequest">The <see cref="WsTrustRequest"/> to serialize into the message.</param>
        /// <returns>The <see cref="Message" /> object that represents the WS-Trust message.</returns>
        private static Message CreateRequest(WsTrustRequest trustRequest)
        {
            _ = trustRequest ?? throw new ArgumentNullException(nameof(trustRequest));
            return Message.CreateMessage(MessageVersion.Soap12WSAddressing10,
                                         GetRequestAction(trustRequest),
                                         new WSTrustRequestBodyWriter(trustRequest, new WsTrustSerializer()));
        }

        /// <summary>
        /// Gets the WS-Addressing SOAP action that corresponds to the requestType and WS-Trust version.
        /// </summary>
        /// <param name="requestType">The type of WS-Trust request. This parameter must be one of the
        /// string constants in <see cref="WsTrustActions" />.</param>
        /// <param name="trustVersion">The <see cref="WsTrustVersion" /> of the request.</param>
        /// <returns>The WS-Addressing action to use.</returns>
        public static string GetRequestAction(WsTrustRequest trustRequest)
        {
            _ = trustRequest ?? throw new ArgumentNullException(nameof(trustRequest));

            WsTrustActions wsTrustActions;
            if (trustRequest.WsTrustVersion == WsTrustVersion.Trust13)
                wsTrustActions = WsTrustActions.Trust13;
            else if (trustRequest.WsTrustVersion == WsTrustVersion.TrustFeb2005)
                wsTrustActions = WsTrustActions.TrustFeb2005;
            else if (trustRequest.WsTrustVersion == WsTrustVersion.Trust14)
                wsTrustActions = WsTrustActions.Trust14;
            else
                throw new NotSupportedException($"Trust version not supported: '{trustRequest.WsTrustVersion}'.");

            if (trustRequest.RequestType.Equals(wsTrustActions.Issue))
                return wsTrustActions.IssueRequest;
            else if (trustRequest.RequestType.Equals(wsTrustActions.Cancel))
                return wsTrustActions.CancelRequest;
            else if (trustRequest.RequestType.Equals(wsTrustActions.Renew))
                return wsTrustActions.RenewRequest;
            else if (trustRequest.RequestType.Equals(wsTrustActions.Validate))
                return wsTrustActions.ValidateRequest;
            else
                throw new NotSupportedException($"Trust request not supported: '{trustRequest.RequestType}.'");
        }
    }

    public class WSTrustRequestBodyWriter : BodyWriter
    {
        WsTrustSerializer trustSerializer;
        WsTrustRequest _trustRequest;

        /// <summary>
        /// Constructor for the WSTrustRequestBodyWriter.
        /// </summary>
        /// <param name="trustRequest">The RequestSecurityToken object to be serialized in the outgoing Message.</param>
        /// <param name="trustSerializer">Serializer is responsible for writing the requestSecurityToken into a XmlDictionaryWritter.</param>
        public WSTrustRequestBodyWriter(WsTrustRequest trustRequest, WsTrustSerializer trustSerializer) : base(true)
        {
            _ = trustRequest ?? throw new ArgumentNullException(nameof(trustRequest));
            _ = trustSerializer ?? throw new ArgumentNullException(nameof(trustSerializer));

            _trustRequest = trustRequest;
            this.trustSerializer = trustSerializer;
        }

        /// <summary>
        /// Override of the base class method. Serializes the requestSecurityToken to the outgoing stream.
        /// </summary>
        /// <param name="writer">Writer into which the requestSecurityToken should be written.</param>
        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            trustSerializer.WriteRequest(writer, _trustRequest.WsTrustVersion, _trustRequest);
        }
    }
}