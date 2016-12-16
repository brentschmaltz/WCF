// ----------------------------------------------------------------------------
// BindingUtilities
//  - some helpful methods to tweak WCF bindings
// ----------------------------------------------------------------------------

using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;

namespace WcfUtilities
{
    public static class BindingUtilities
    {
        public static void AddSignedEndpointSupportingTokenParameters(CustomBinding cb, SecurityTokenParameters stp, SecurityTokenInclusionMode stim)
        {
            SecurityBindingElement sbe;
            if (TryGetSecurityBindingElement(cb, out sbe))
            {
                sbe.EndpointSupportingTokenParameters.Signed.Add(stp);
            }

            stp.InclusionMode = stim;
        }

        public static void AddSignedEndpointSupportingTokenParameters(CustomBinding cb, SecurityTokenParameters stp)
        {
            SecurityBindingElement sbe;
            if (TryGetSecurityBindingElement(cb, out sbe))
            {
                sbe.EndpointSupportingTokenParameters.Signed.Add(stp);
            }
        }

        public static void AddSignedEncryptedEndpointSupportingTokenParameters(CustomBinding cb, SecurityTokenParameters stp, MessageProtectionOrder protectionOrder)
        {
            SecurityBindingElement sbe;
            if (TryGetSecurityBindingElement(cb, out sbe))
            {
                sbe.EndpointSupportingTokenParameters.SignedEncrypted.Add(stp);
                var ssbe = sbe as SymmetricSecurityBindingElement;
                if (ssbe != null)
                    ssbe.MessageProtectionOrder = protectionOrder;
            }
        }

        public static void AddEndpointEndorsingTokenParameters(CustomBinding cb, SecurityTokenParameters stp)
        {
            SecurityBindingElement sbe;
            if (TryGetSecurityBindingElement(cb, out sbe))
                sbe.EndpointSupportingTokenParameters.Endorsing.Add(stp);
        }

        public static void AddMexEndpoint(ServiceHost serviceHost, string baseAddress, bool enableHttp)
        {
            var serviceMetadataBehavior = new ServiceMetadataBehavior();
            serviceMetadataBehavior.HttpGetEnabled = enableHttp;
            if (enableHttp)
            {
                serviceMetadataBehavior.HttpGetUrl = new Uri(baseAddress);
                serviceMetadataBehavior.HttpGetUrl = new Uri(baseAddress + "/mex");
            }

            serviceHost.Description.Behaviors.Add(serviceMetadataBehavior);

            if (string.Compare(Uri.UriSchemeHttps, baseAddress.Substring(0, 5), true) == 0)
                serviceHost.AddServiceEndpoint(typeof(IMetadataExchange), MetadataExchangeBindings.CreateMexHttpsBinding(), baseAddress + "/mex");
            else if (string.Compare(Uri.UriSchemeHttp, baseAddress.Substring(0, 4), true) == 0)
                serviceHost.AddServiceEndpoint(typeof(IMetadataExchange), MetadataExchangeBindings.CreateMexHttpBinding(), baseAddress + "/mex");
            else if (string.Compare(Uri.UriSchemeNetTcp, baseAddress.Substring(0, 6), true) == 0)
                serviceHost.AddServiceEndpoint(typeof(IMetadataExchange), MetadataExchangeBindings.CreateMexTcpBinding(), baseAddress + "/mex");
            else
                Console.WriteLine("Can't add MexEndpoint");
        }

        static Binding BuildBinding( SecurityBindingElement sbe )
        {
            sbe.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12;
            var bec = new BindingElementCollection();

            bec.Add( sbe );
            bec.Add( new TextMessageEncodingBindingElement() );
            bec.Add( new HttpTransportBindingElement() );

            CustomBinding binding = new CustomBinding( bec );
            binding.Name = "WcfUtilities.CustomBinding";
            binding.Namespace = "http://IdentityModel.samples.org";

            return binding;

        }

        public static CustomBinding CreateCustomBindingWithMessageProtectionOrder(WSHttpBinding binding, MessageProtectionOrder messageProtectionOrder)
        {
            var customBinding = new CustomBinding(binding);
            var securityBindingElement = GetSecurityBindingElement(customBinding);
            if (securityBindingElement == null)
                throw new InvalidOperationException($"{typeof(SecurityBindingElement)} not found in: {binding.GetType()}.");

            SetMessageProtectionOrder(securityBindingElement, messageProtectionOrder);

            return customBinding;
        }

        public static void SetMessageProtectionOrder(CustomBinding customBinding, MessageProtectionOrder messageProtectionOrder)
        {
            var securityBindingElement = GetSecurityBindingElement(customBinding);
            if (securityBindingElement == null)
                throw new InvalidOperationException($"{typeof(SecurityBindingElement)} not found in: {customBinding.GetType()}.");

            SetMessageProtectionOrder(securityBindingElement, messageProtectionOrder);
        }

        // This method creates a CustomBinding based on a WSFederationHttpBinding which does not use secure conversation.
        public static CustomBinding CreateFederationBindingWithoutSecureSession( WS2007FederationHttpBinding inputBinding )
        {

            var outputBinding = new CustomBinding( inputBinding.CreateBindingElements() );
            var security = outputBinding.Elements.Find<SecurityBindingElement>();

            SecureConversationSecurityTokenParameters secureConversation;
            if ( WSFederationHttpSecurityMode.Message == inputBinding.Security.Mode )
            {
                var symmetricSecurity = security as SymmetricSecurityBindingElement;
                secureConversation = symmetricSecurity.ProtectionTokenParameters as SecureConversationSecurityTokenParameters;
            }
            // If the security mode is message, then the secure session settings are the endorsing token parameters.
            else if ( WSFederationHttpSecurityMode.TransportWithMessageCredential == inputBinding.Security.Mode )
            {
                var transportSecurity = security as TransportSecurityBindingElement;
                secureConversation = transportSecurity.EndpointSupportingTokenParameters.Endorsing[0] as SecureConversationSecurityTokenParameters;
            }
            else
            {
                throw new NotSupportedException( String.Format( "Unhandled security mode {0}.", inputBinding.Security.Mode ) );
            }

            var securityIndex = outputBinding.Elements.IndexOf( security );
            outputBinding.Elements[securityIndex] = secureConversation.BootstrapSecurityBindingElement;

            return outputBinding;
        }

        // This method creates a CustomBinding based on a WSFederationHttpBinding which does not use secure conversation.
        public static CustomBinding CreateFederationBindingWithoutSecureSession( WSFederationHttpBinding inputBinding )
        {
            var outputBinding = new CustomBinding( inputBinding.CreateBindingElements() );
            var security = outputBinding.Elements.Find<SecurityBindingElement>();
            SecureConversationSecurityTokenParameters secureConversation;
            if ( WSFederationHttpSecurityMode.Message == inputBinding.Security.Mode )
            {
                var symmetricSecurity = security as SymmetricSecurityBindingElement;
                secureConversation = symmetricSecurity.ProtectionTokenParameters as SecureConversationSecurityTokenParameters;
            }
            else if ( WSFederationHttpSecurityMode.TransportWithMessageCredential == inputBinding.Security.Mode )
            {
                var transportSecurity = security as TransportSecurityBindingElement;
                secureConversation = transportSecurity.EndpointSupportingTokenParameters.Endorsing[0] as SecureConversationSecurityTokenParameters;
            }
            else
            {
                throw new NotSupportedException( String.Format( "Unhandled security mode {0}.", inputBinding.Security.Mode ) );
            }

            var securityIndex = outputBinding.Elements.IndexOf( security );
            outputBinding.Elements[securityIndex] = secureConversation.BootstrapSecurityBindingElement;

            return outputBinding;
        }

        public static Binding CreateWsHttpWindowsWithSignedSupportingToken()
        {
            return CreateWsHttpWindowsWithSignedSupportingToken(null);
        }

        public static Binding CreateWsHttpWindowsWithSignedSupportingToken(SecurityTokenParameters stp)
        {
            var wsHttpBinding = new WSHttpBinding();
            wsHttpBinding.Security.Message.NegotiateServiceCredential = true;
            wsHttpBinding.Security.Message.EstablishSecurityContext = false;
            wsHttpBinding.ReliableSession.Enabled = false;

            var cb = new CustomBinding(wsHttpBinding);
            if (stp != null)
                AddSignedEndpointSupportingTokenParameters(cb, stp, SecurityTokenInclusionMode.AlwaysToRecipient);

            return cb;
        }

        public static void DisplayBindingInfoToConsole(ServiceHost serviceHost)
        {
            for (int i = 0; i < serviceHost.ChannelDispatchers.Count; i++)
            {
                var channelDispatcher = serviceHost.ChannelDispatchers[i] as ChannelDispatcher;
                if (channelDispatcher != null)
                    for (int j = 0; j < channelDispatcher.Endpoints.Count; j++)
                        Console.WriteLine("Listening on " + channelDispatcher.Endpoints[j].EndpointAddress + "...");
            }
        }

        public static Binding GetKerbOneShotBinding()
        {
            var sbe = SecurityBindingElement.CreateKerberosBindingElement();
            sbe.RequireSignatureConfirmation = false;
            sbe.KeyEntropyMode = SecurityKeyEntropyMode.CombinedEntropy;

            return BuildBinding(sbe);
        }

        public static Binding GetMutualCertBinding()
        {
            var sbe = SecurityBindingElement.CreateMutualCertificateBindingElement();
            sbe.KeyEntropyMode = SecurityKeyEntropyMode.CombinedEntropy;

            return BuildBinding(sbe);
        }

        public static Binding GetStsSspiBinding()
        {
            var ssbe = SecurityBindingElement.CreateSspiNegotiationBindingElement(true);
            ssbe.RequireSignatureConfirmation = false;
            ssbe.KeyEntropyMode = SecurityKeyEntropyMode.CombinedEntropy;

            return BuildBinding(ssbe);
        }

        public static Binding GetSymmetricIssuedBinding()
        {
            var bec = new BindingElementCollection();
            var securityBindingElment = new SymmetricSecurityBindingElement(new IssuedSecurityTokenParameters());
            bec.Add(securityBindingElment);
            bec.Add(new TextMessageEncodingBindingElement());
            bec.Add(new HttpTransportBindingElement());
            var cb = new CustomBinding(bec);

            cb.Name = "WcfUtilities.GetSymmetricIssuedBinding";
            cb.Namespace = "http://tempuri.org/Service";

            return cb;
        }

        public static Binding GetStsIssuedTokenBinding()
        {
            var istp = new IssuedSecurityTokenParameters(SecurityTokenTypes.Saml);
            var sbe = SecurityBindingElement.CreateIssuedTokenBindingElement(istp);
            sbe.KeyEntropyMode = SecurityKeyEntropyMode.CombinedEntropy;

            return BuildBinding(sbe);
        }

        public static SecurityBindingElement GetSecurityBindingElement(BindingElementCollection bec)
        {
            foreach (BindingElement be in bec)
            {
                var sbe = be as SecurityBindingElement;
                if (sbe != null)
                {
                    return sbe;
                }
            }

            return null;
        }

        public static CustomBinding GetSspiBinding()
        {
            var bindingElements = new Collection<BindingElement>();
            var security = SecurityBindingElement.CreateSecureConversationBindingElement( SecurityBindingElement.CreateSspiNegotiationBindingElement( true ), true );
            bindingElements.Add( security );
            var http = new HttpTransportBindingElement();
            bindingElements.Add( http );

            var binding = new CustomBinding( bindingElements );
            binding.Name = "WcfUtilities.GetSspiBinding";
            binding.Namespace = "http://tempuri.org/bindings";
            return binding;
        }

        public static SecurityBindingElement GetSecurityBindingElement(CustomBinding customBinding)
        {
            for (int i = 0; i < customBinding.Elements.Count; i++)
            {
                if (customBinding.Elements[i] is SecurityBindingElement)
                    return customBinding.Elements[i] as SecurityBindingElement;
            }

            return null;
        }

        public static Binding GetBinding(string binding)
        {
            switch (binding)
            {
                case "System.ServiceModel.BasicHttpBinding":
                    return new BasicHttpBinding();

                case "System.ServiceModel.WSHttpBinding":
                    return new WSHttpBinding();

                case "System.ServiceModel.WS2007HttpBinding":
                    return new WS2007HttpBinding();

                case "System.ServiceModel.NetTcpBinding":
                    return new NetTcpBinding();

                case "System.ServiceModel.WSDualHttpBinding":
                    return new WSDualHttpBinding();

                case "System.ServiceModel.WSFederationBinding":
                    return new WSFederationHttpBinding();

                case "System.ServiceModel.WS2007FederationBinding":
                    return new WS2007FederationHttpBinding();

                case "System.ServiceModel.NetNamedPipeBinding":
                    return new NetNamedPipeBinding();

                case "System.ServiceModel.NetMsmqBinding":
                    return new NetMsmqBinding();

                case "System.ServiceModel.Custom":
                    return new CustomBinding();
            }

            throw new ArgumentOutOfRangeException("binding", binding, "Unknown Binding");

        }

        public static IssuedSecurityTokenParameters IssuedSecurityTokenParameters(string issuerAddress, Binding binding, SecurityKeyType keyType, string tokenType)
        {
            var tokenParameters = new IssuedSecurityTokenParameters();
            tokenParameters.IssuerAddress = new EndpointAddress(new Uri(issuerAddress));
            tokenParameters.IssuerBinding = binding;
            tokenParameters.KeyType = keyType;
            tokenParameters.TokenType = tokenType;
            return tokenParameters;
        }

        public static BasicHttpSecurityMode MapToBasicHttpSecurityMode(string securityModeType)
        {
            switch (securityModeType)
            {
                case "System.ServiceModel.BasicHttpSecurityMode.None":
                    return BasicHttpSecurityMode.None;

                case "System.ServiceModel.BasicHttpSecurityMode.Transport":
                    return BasicHttpSecurityMode.Transport;

                case "System.ServiceModel.BasicHttpSecurityMode.Message":
                    return BasicHttpSecurityMode.Message;

                case "System.ServiceModel.BasicHttpSecurityMode.TransportWithMessageCredential":
                    return BasicHttpSecurityMode.TransportWithMessageCredential;

                case "System.ServiceModel.BasicHttpSecurityMode.TransportCredentialOnly":
                    return BasicHttpSecurityMode.TransportCredentialOnly;

                default:
                    throw new ArgumentOutOfRangeException("securityModeType", securityModeType, "Security Mode NotValid for BasicHttpSecurityMode");
            }
        }

        public static NetMsmqSecurityMode MapToNetMsmqSecurityMode(string securityModeType)
        {
            switch (securityModeType)
            {
                case "System.ServiceModel.NetMsmqSecurityMode.None":
                    return NetMsmqSecurityMode.None;

                case "System.ServiceModel.NetMsmqSecurityMode.Transport":
                    return NetMsmqSecurityMode.Transport;

                case "System.ServiceModel.NetMsmqSecurityMode.Message":
                    return NetMsmqSecurityMode.Message;

                case "System.ServiceModel.NetMsmqSecurityMode.Both":
                    return NetMsmqSecurityMode.Both;

                default:
                    throw new ArgumentOutOfRangeException("securityModeType", securityModeType, "Security Mode not valid for NetMsmqBinding");
            }
        }

        public static NetNamedPipeSecurityMode MapToNetNamedPipeSecurityMode(String securityModeType)
        {
            switch (securityModeType)
            {
                case "System.ServiceModel.NetNamedPipeSecurityMode.None":
                    return NetNamedPipeSecurityMode.None;

                case "System.ServiceModel.NetNamedPipeSecurityMode.Transport":
                    return NetNamedPipeSecurityMode.Transport;

                default:
                    throw new ArgumentOutOfRangeException("securityModeType", securityModeType, "Security Mode not valid for MapToNetNamedPipeSecurityMode");
            }
        }

        public static SecurityMode MapToSecurityMode(string securityModeType)
        {
            switch (securityModeType)
            {
                case "System.ServiceModel.SecurityMode.None":
                    return SecurityMode.None;

                case "System.ServiceModel.SecurityMode.Transport":
                    return SecurityMode.Transport;

                case "System.ServiceModel.SecurityMode.Message":
                    return SecurityMode.Message;

                case "System.ServiceModel.SecurityMode.TransportWithMessageCredential":
                    return SecurityMode.TransportWithMessageCredential;

                default:
                    throw new ArgumentOutOfRangeException("securityModeType", securityModeType, "Security Mode is not valid for Binding");
            }
        }

        public static WSDualHttpSecurityMode MapToWSDualHttpSecurityMode(string securityModeType)
        {
            switch (securityModeType)
            {
                case "System.ServiceModel.WSDualHttpSecurityMode.None":
                    return WSDualHttpSecurityMode.None;

                case "System.ServiceModel.WSDualHttpSecurityMode.Message":
                    return WSDualHttpSecurityMode.Message;

                default:
                    throw new ArgumentOutOfRangeException("securityModeType", securityModeType, "Security Mode not valid for WSDualHttpSecurityMode");
            }
        }

        public static WSFederationHttpSecurityMode MapToWSFederationSecurityMode(string securityModeType)
        {
            switch (securityModeType)
            {
                case "System.ServiceModel.WSFederationSecurityMode.None":
                    return WSFederationHttpSecurityMode.None;

                case "System.ServiceModel.WSFederationSecurityMode.Message":
                    return WSFederationHttpSecurityMode.Message;

                case "System.ServiceModel.TransportWithMessageCredential.Message":
                    return WSFederationHttpSecurityMode.TransportWithMessageCredential;

                default:
                    throw new ArgumentOutOfRangeException("securityModeType", securityModeType, "Security Mode not valid for WSFederationSecurityMode");
            }
        }

        public static void SetMaxTimeout(System.ServiceModel.Channels.Binding binding, TimeSpan timeSpan)
        {
            binding.CloseTimeout = timeSpan;
            binding.OpenTimeout = timeSpan;
            binding.ReceiveTimeout = timeSpan;
            binding.SendTimeout = timeSpan;
        }

        public static void SetMaxTimeout(System.ServiceModel.Channels.Binding binding)
        {
            SetMaxTimeout(binding, TimeSpan.MaxValue);
        }

        public static void SetMessageProtectionOrder(SecurityBindingElement securityBindingElement, MessageProtectionOrder messageProtectionOrder)
        {
            var ssbe = securityBindingElement as SymmetricSecurityBindingElement;
            if (ssbe != null)
            {
                ssbe.MessageProtectionOrder = messageProtectionOrder;
                return;
            }

            var asbe = securityBindingElement as AsymmetricSecurityBindingElement;
            if (asbe != null)
            {
                asbe.MessageProtectionOrder = messageProtectionOrder;
                return;
            }

            throw new InvalidOperationException($"Unable to set 'MessageProtectionOrder' on securityBindingElement: {securityBindingElement}");
        }

        public static void SetSctCookieMode(CustomBinding customBinding, bool cookieMode)
        {
            if (customBinding == null)
                throw new ArgumentNullException(nameof(customBinding));

            var sbe = GetSecurityBindingElement(customBinding);
            var ssbe = sbe as SymmetricSecurityBindingElement;
            if (ssbe != null)
            {
                var scstp = ssbe.ProtectionTokenParameters as SecureConversationSecurityTokenParameters;
                if (scstp != null)
                    scstp.RequireCancellation = !cookieMode;

                return;
            }

            var tsbe = sbe as TransportSecurityBindingElement;
            if (tsbe != null)
            {
                if (tsbe.EndpointSupportingTokenParameters != null && tsbe.EndpointSupportingTokenParameters.Endorsing != null && tsbe.EndpointSupportingTokenParameters.Endorsing.Count > 0)
                {
                    var sstp = tsbe.EndpointSupportingTokenParameters.Endorsing[0] as SspiSecurityTokenParameters;
                    if (sstp != null)
                        sstp.RequireCancellation = !cookieMode;

                    var scstp = tsbe.EndpointSupportingTokenParameters.Endorsing[0] as SecureConversationSecurityTokenParameters;
                    if (scstp != null)
                        scstp.RequireCancellation = !cookieMode;
                }
            }

            throw new InvalidOperationException($"Unable to set SctCookieMode on customBinding: {customBinding}");
        }

        public static void SetReplayDetection(CustomBinding customBinding, bool replayDetection)
        {
            var securityBindingElement = GetSecurityBindingElement(customBinding.Elements);
            if (securityBindingElement == null)
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unable to find '{0}' in customBinding", typeof(SecurityBindingElement)));

            securityBindingElement.LocalServiceSettings.DetectReplays = replayDetection;
        }

        public static void SetSecurityHeaderLayout(CustomBinding customBinding, SecurityHeaderLayout securityHeaderLayout)
        {
            var securityBindingElement = GetSecurityBindingElement(customBinding.Elements);
            if (securityBindingElement == null)
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unable to find '{0}' in customBinding", typeof(SecurityBindingElement)));

            securityBindingElement.SecurityHeaderLayout = securityHeaderLayout;
        }

        public static bool TryGetSecurityBindingElement(CustomBinding customBinding, out SecurityBindingElement sbe)
        {
            sbe = null;

            for (int i = 0; i < customBinding.Elements.Count; i++)
            {
                if (customBinding.Elements[i] is SecurityBindingElement)
                {
                    sbe = customBinding.Elements[i] as SecurityBindingElement;
                    return true;
                }
            }
            return false;
        }
    }
}
