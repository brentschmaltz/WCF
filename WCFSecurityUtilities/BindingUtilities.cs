using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Net.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Xml;

namespace WCFSecurityUtilities
{
    public static class BindingUtilities
    {
        public static void AddEndpointEndorsingTokenParameters(CustomBinding cb, SecurityTokenParameters stp)
        {
            if (TryGetSecurityBindingElement(cb, out SecurityBindingElement sbe))
                sbe.EndpointSupportingTokenParameters.Endorsing.Add(stp);
        }

        public static void AddMexEndpoint(ServiceHost serviceHost, string baseAddress, bool enableHttp)
        {
            var smb = new ServiceMetadataBehavior
            {
                HttpGetEnabled = enableHttp
            };

            if (enableHttp)
                smb.HttpGetUrl = new Uri(baseAddress);

            serviceHost.Description.Behaviors.Add(smb);

            if (string.Compare(Uri.UriSchemeHttps, baseAddress.Substring(0, 5), true) == 0)
                serviceHost.AddServiceEndpoint(typeof(IMetadataExchange), MetadataExchangeBindings.CreateMexHttpsBinding(), baseAddress + "/mex");
            else if (string.Compare(Uri.UriSchemeHttp, baseAddress.Substring(0, 4), true) == 0)
                serviceHost.AddServiceEndpoint(typeof(IMetadataExchange), MetadataExchangeBindings.CreateMexHttpBinding(), baseAddress + "/mex");
            else if (string.Compare(Uri.UriSchemeNetTcp, baseAddress.Substring(0, 6), true) == 0)
                serviceHost.AddServiceEndpoint(typeof(IMetadataExchange), MetadataExchangeBindings.CreateMexTcpBinding(), baseAddress + "/mex");
        }

        public static void AddSignedEndpointSupportingTokenParameters(CustomBinding cb, SecurityTokenParameters stp, SecurityTokenInclusionMode stim)
        {
            if (TryGetSecurityBindingElement(cb, out SecurityBindingElement sbe))
                sbe.EndpointSupportingTokenParameters.Signed.Add(stp);

            stp.InclusionMode = stim;
        }

        public static void AddSignedEndpointSupportingTokenParameters(CustomBinding cb, SecurityTokenParameters stp)
        {
            if (TryGetSecurityBindingElement(cb, out SecurityBindingElement sbe))
                sbe.EndpointSupportingTokenParameters.Signed.Add(stp);
        }

        public static void AddSignedEncryptedEndpointSupportingTokenParameters(CustomBinding cb, SecurityTokenParameters stp, MessageProtectionOrder protectionOrder)
        {
            if (TryGetSecurityBindingElement(cb, out SecurityBindingElement sbe))
            {
                sbe.EndpointSupportingTokenParameters.SignedEncrypted.Add(stp);
                if (sbe is SymmetricSecurityBindingElement ssbe)
                    ssbe.MessageProtectionOrder = protectionOrder;
            }
        }

        public static Binding BuildBinding(SecurityBindingElement sbe)
        {
            sbe.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12;

            var bec = new BindingElementCollection
            {
                sbe,
                new TextMessageEncodingBindingElement(),
                new HttpTransportBindingElement()
            };

            return new CustomBinding(bec)
            {
                Name = "IdentityModelUtilities",
                Namespace = "http://IdentityModel.samples.org"
            };
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

        public static Binding GetFedBinding()
        {
            var binding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.Message, false);
            binding.Security.Message.NegotiateServiceCredential = false;
            return binding;
        }

        public static CustomBinding CreateFederationBindingWithoutSecureSession(WS2007FederationHttpBinding inputBinding)
        {
            var outputBinding = new CustomBinding(inputBinding.CreateBindingElements());
            var sbe = outputBinding.Elements.Find<SecurityBindingElement>();

            SecureConversationSecurityTokenParameters secureConversation;
            if (WSFederationHttpSecurityMode.Message == inputBinding.Security.Mode)
            {
                var ssbe = sbe as SymmetricSecurityBindingElement;
                secureConversation = ssbe.ProtectionTokenParameters as SecureConversationSecurityTokenParameters;
            }
            else if (WSFederationHttpSecurityMode.TransportWithMessageCredential == inputBinding.Security.Mode)
            {
                var tsbe = sbe as TransportSecurityBindingElement;
                secureConversation = tsbe.EndpointSupportingTokenParameters.Endorsing[0] as SecureConversationSecurityTokenParameters;
            }
            else
            {
                throw new NotSupportedException(string.Format("Unhandled security mode {0}.", inputBinding.Security.Mode));
            }

            int securityIndex = outputBinding.Elements.IndexOf(sbe);
            outputBinding.Elements[securityIndex] = secureConversation.BootstrapSecurityBindingElement;
            return outputBinding;
        }

        public static CustomBinding CreateFederationBindingWithoutSecureSession(WSFederationHttpBinding inputBinding)
        {
            var outputBinding = new CustomBinding(inputBinding.CreateBindingElements());
            var sbe = outputBinding.Elements.Find<SecurityBindingElement>();
            int securityIndex = outputBinding.Elements.IndexOf(sbe);
            if (WSFederationHttpSecurityMode.Message == inputBinding.Security.Mode)
            {
                var ssbe = sbe as SymmetricSecurityBindingElement;
                outputBinding.Elements[securityIndex] = (ssbe.ProtectionTokenParameters as SecureConversationSecurityTokenParameters).BootstrapSecurityBindingElement;
            }
            else if (WSFederationHttpSecurityMode.TransportWithMessageCredential == inputBinding.Security.Mode)
            {
                var tsbe = sbe as TransportSecurityBindingElement;
                outputBinding.Elements[securityIndex] = (tsbe.EndpointSupportingTokenParameters.Endorsing[0] as SecureConversationSecurityTokenParameters).BootstrapSecurityBindingElement;
            }
            else
            {
                throw new NotSupportedException(string.Format("Unhandled security mode {0}.", inputBinding.Security.Mode));
            }

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

        public static void DisplayBindingInfoToConsole(ServiceHost serviceHost, string message)
        {
            Console.WriteLine(message);
            Console.WriteLine("====================");
            DisplayBindingInfoToConsole(serviceHost);
            Console.WriteLine("");
        }

        public static void DisplayBindingInfoToConsole(ServiceHost serviceHost)
        {

            foreach(var item in serviceHost.ChannelDispatchers)
            {
                if (item is ChannelDispatcher channelDispatcher)
                {
                    for (int j = 0; j < channelDispatcher.Endpoints.Count; j++)
                    {
                        EndpointDispatcher endpointDispatcher = channelDispatcher.Endpoints[j];
                        Console.WriteLine("Listening on " + endpointDispatcher.EndpointAddress + "...");
                    }
                }
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

        public static SecurityBindingElement GetSecurityBindingElement(BindingElementCollection bec)
        {
            foreach (BindingElement be in bec)
            {
                if (be is SecurityBindingElement sbe)
                    return sbe;
            }

            return null;
        }

        public static Binding GetStsSspiBinding()
        {
            var ssbe = SecurityBindingElement.CreateSspiNegotiationBindingElement(true);
            ssbe.RequireSignatureConfirmation = false;
            ssbe.KeyEntropyMode = SecurityKeyEntropyMode.CombinedEntropy;

            return BuildBinding(ssbe);
        }

        public static Binding GetStsIssuedTokenBinding()
        {
            var istp = new IssuedSecurityTokenParameters(SecurityTokenTypes.Saml);
            var sbe = SecurityBindingElement.CreateIssuedTokenBindingElement(istp);
            sbe.KeyEntropyMode = SecurityKeyEntropyMode.CombinedEntropy;

            return BuildBinding(sbe);
        }

        public static Binding GetSymmetricIssuedBinding()
        {
            var bec = new BindingElementCollection();
            var ssbe = new SymmetricSecurityBindingElement(new IssuedSecurityTokenParameters());
            bec.Add(ssbe);
            bec.Add(new TextMessageEncodingBindingElement());
            bec.Add(new HttpTransportBindingElement());

            return new CustomBinding(bec)
            {
                Name = "Service",
                Namespace = "http://tempuri.org/Service"
            };
        }

        public static CustomBinding GetStsBinding()
        {
            var wsHttpBinding = new WSHttpBinding(SecurityMode.Message);
            var bec = wsHttpBinding.CreateBindingElements();
            foreach (BindingElement be in bec)
            {
                SecurityBindingElement sbe1 = (be as SecurityBindingElement);
                if (sbe1 != null)
                {
                    MessageSecurityVersion msv = sbe1.MessageSecurityVersion;
                    LocalClientSecuritySettings lcs = sbe1.LocalClientSettings;
                    LocalServiceSecuritySettings lss = sbe1.LocalServiceSettings;
                }
            }

            var sbe = SecurityBindingElement.CreateSspiNegotiationBindingElement();
            return new CustomBinding(sbe, new HttpTransportBindingElement());
        }

        public static CustomBinding GetSspiBinding()
        {
            var bec = new Collection<BindingElement>
            {
                SecurityBindingElement.CreateSecureConversationBindingElement( SecurityBindingElement.CreateSspiNegotiationBindingElement( true ), true ),
                new HttpTransportBindingElement()
            };

            return new CustomBinding(bec)
            {
                Name = "GetSspiBinding",
                Namespace = "http://tempuri.org/bindings"
            };
        }

        public static IssuedSecurityTokenParameters IssuedSecurityTokenParameters(string issuerAddress, Binding binding, SecurityKeyType keyType, string tokenType)
        {
            return new IssuedSecurityTokenParameters
            {
                IssuerAddress = new EndpointAddress(new Uri(issuerAddress)),
                IssuerBinding = binding,
                KeyType = keyType,
                TokenType = tokenType
            };
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

        public static NetNamedPipeSecurityMode MapToNetNamedPipeSecurityMode(string securityModeType)
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

        public static void ReplaceCredentialsOnChannelFactory(ClientCredentials clientCredentials, ChannelFactory channelFactory)
        {
            channelFactory.Endpoint.Behaviors.Remove<ClientCredentials>();
            channelFactory.Endpoint.Behaviors.Add(clientCredentials);
        }

        public static void ReplaceCredentialsOnServiceHost(ServiceCredentials serviceCredentials, ServiceHost serviceHost)
        {
            serviceHost.Description.Behaviors.Remove<ServiceCredentials>();
            serviceHost.Description.Behaviors.Add(serviceCredentials);
        }

        public static void SetMessageProtectionOrder(SecurityBindingElement securityBindingElement, MessageProtectionOrder mpo)
        {
            if (securityBindingElement is SymmetricSecurityBindingElement ssbe)
                ssbe.MessageProtectionOrder = mpo;
            else if (securityBindingElement is AsymmetricSecurityBindingElement asbe)
                asbe.MessageProtectionOrder = mpo;
        }

        public static Binding SetRequireCancellation(Binding binding, bool requireCancellation)
        {
            var bec = binding.CreateBindingElements();
            SecurityBindingElement sbe = null;
            foreach (BindingElement be in bec)
            {
                if (be is SecurityBindingElement)
                {
                    sbe = be as SecurityBindingElement;
                    break;
                }
            }

            if (sbe is SymmetricSecurityBindingElement ssbe)
            {
                if (ssbe.ProtectionTokenParameters is SecureConversationSecurityTokenParameters scstp)
                    scstp.RequireCancellation = requireCancellation;

                return new CustomBinding(bec);
            }

            if (sbe is TransportSecurityBindingElement tsbe)
            {
                if (tsbe.EndpointSupportingTokenParameters != null && tsbe.EndpointSupportingTokenParameters.Endorsing != null && tsbe.EndpointSupportingTokenParameters.Endorsing.Count > 0)
                {
                    if (tsbe.EndpointSupportingTokenParameters.Endorsing[0] is SspiSecurityTokenParameters sstp)
                    {
                        sstp.RequireCancellation = requireCancellation;
                        return new CustomBinding(bec);
                    }


                    if (tsbe.EndpointSupportingTokenParameters.Endorsing[0] is SecureConversationSecurityTokenParameters scstp)
                    {
                        scstp.RequireCancellation = requireCancellation;
                        return new CustomBinding(bec);
                    }
                }
            }

            return binding;
        }

        public static void SetMessageSecurityVersion(CustomBinding cb, MessageSecurityVersion msv)
        {
            if (TryGetSecurityBindingElement(cb, out SecurityBindingElement sbe))
                sbe.MessageSecurityVersion = msv;
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

        public static void TurnOffSecureConversation(CustomBinding cb)
        {
            if (TryGetSecurityBindingElement(cb, out SecurityBindingElement sbe))
            {
            }
        }
    }

    public class FakeSecureBindingElement : BindingElement, ITransportTokenAssertionProvider
    {
        public override BindingElement Clone()
        {
            return new FakeSecureBindingElement();
        }

        public override T GetProperty<T>(BindingContext context)
        {
            if (typeof(T) == typeof(ISecurityCapabilities))
            {
                return (T)(object)new SecurityCapabilities();
            }
            else
            {
                return context.GetInnerProperty<T>();
            }
        }

        public XmlElement GetTransportTokenAssertion()
        {
            return null;
        }

        class SecurityCapabilities : ISecurityCapabilities
        {
            public ProtectionLevel SupportedRequestProtectionLevel { get { return ProtectionLevel.EncryptAndSign; } }
            public ProtectionLevel SupportedResponseProtectionLevel { get { return ProtectionLevel.EncryptAndSign; } }
            public bool SupportsClientAuthentication { get { return false; } }
            public bool SupportsClientWindowsIdentity { get { return false; } }
            public bool SupportsServerAuthentication { get { return true; } }
        }

    }
}
