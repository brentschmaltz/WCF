﻿using System;
using System.Globalization;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel.Web;
using WCFSecurityUtilities;

// netsh http add sslcert ipport=127.0.0.1:443 certhash=5008e9b6f4995c472a67c16cc18dad36acf4be38 appid={00112233-4455-6677-8899-AABBCCDDEEFF}
// netsh http add sslcert ipport=127.0.0.1:5443 certhash=cfb894905fb847d8da1d3df6886ebe22b3b533d8 appid={00112233-4455-6677-8899-AABBCCDDEEFF}

namespace SelfHostSTS
{
    class Program
    {
        private static string _endpointNameMessageIWA = "trust/13/messageIWA";
        private static string WindowsTransport = "trust/13/windowsTransport";
        private static string WindowsMixed = "trust/13/windowsmixed";
        private static string _endpointNameTransportIssuerSaml20 = "trust/13/transportIssueSaml20";
        private static string _endpointNameTransportIssuerSaml = "trust/13/transportIssueSaml";
        private static string _endpointNameTransportUserName = "trust/13/usernamemixed";

        static void Main(string[] args)
        {
            try
            {
                ConfigureSts();
                SetupWsTrustHost();
                SetupWsFedHost();

                WSFedServiceHost.Open();
                WSTrustServiceHost.Open();

                BindingUtilities.DisplayBindingInfoToConsole(WSFedServiceHost, "WS-Fed endpoints");
                BindingUtilities.DisplayBindingInfoToConsole(WSTrustServiceHost, "WS-Trust endpoints");
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Exception: '{0}'", ex));
            }

            Console.WriteLine("Press any key to stop STS");
            Console.ReadKey();
        }

        private static void AddBinding(WSTrustServiceHost serviceHost, Type bindingType, SecurityMode securityMode, bool establishSecurityContext, string baseAddress, string bindingName, MessageCredentialType messageCredentialType)
        {
            if (serviceHost == null)
                throw new ArgumentNullException(nameof(serviceHost));

            if (bindingType == null)
                throw new ArgumentNullException(nameof(bindingType));

            if (bindingType == typeof(WS2007HttpBinding))
            {
                Binding binding = new WS2007HttpBinding(securityMode);
                (binding as WS2007HttpBinding).Security.Message.EstablishSecurityContext = establishSecurityContext;
                (binding as WS2007HttpBinding).Security.Message.ClientCredentialType = messageCredentialType;

                if (messageCredentialType == MessageCredentialType.IssuedToken && bindingName == _endpointNameTransportIssuerSaml20)
                {
                    var bec = binding.CreateBindingElements();
                    foreach (var be in bec)
                    {
                        if (be is TransportSecurityBindingElement tsbe)
                        {
                            (tsbe.EndpointSupportingTokenParameters.Endorsing[0] as IssuedSecurityTokenParameters).TokenType = TokenTypes.Saml20;
                            break;
                        }
                    }

                    binding = new CustomBinding(bec);
                }

                BindingUtilities.SetMaxTimeout(binding);
                serviceHost.AddServiceEndpoint(typeof(IWSTrust13SyncContract), binding, baseAddress + bindingName);
            }
            else
            {
                throw new NotSupportedException(string.Format(CultureInfo.InvariantCulture, "bindingType is not supported: '{0}'", bindingType));
            }
        }

        private static void AddWsTrustServiceBindings()
        {
            AddBinding(WSTrustServiceHost, typeof(WS2007HttpBinding), SecurityMode.TransportWithMessageCredential, false, HttpsWSTrust13Address, _endpointNameTransportIssuerSaml20, MessageCredentialType.IssuedToken);
            AddBinding(WSTrustServiceHost, typeof(WS2007HttpBinding), SecurityMode.TransportWithMessageCredential, false, HttpsWSTrust13Address, _endpointNameTransportIssuerSaml, MessageCredentialType.IssuedToken);
            AddBinding(WSTrustServiceHost, typeof(WS2007HttpBinding), SecurityMode.Message, false, HttpWSTrust13Address, _endpointNameMessageIWA, MessageCredentialType.Windows);
            AddBinding(WSTrustServiceHost, typeof(WS2007HttpBinding), SecurityMode.TransportWithMessageCredential, false, HttpsWSTrust13Address, _endpointNameTransportUserName, MessageCredentialType.UserName);
            AddBinding(WSTrustServiceHost, typeof(WS2007HttpBinding), SecurityMode.Message, false, HttpWSTrust13Address, WindowsMixed, MessageCredentialType.UserName);

            // Trust 1.3 / transport / windows
            WS2007HttpBinding binding = new WS2007HttpBinding(SecurityMode.Transport, false);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Windows;
            BindingUtilities.SetMaxTimeout(binding);
            WSTrustServiceHost.AddServiceEndpoint(typeof(IWSTrust13SyncContract), binding, HttpsWSTrust13Address + WindowsTransport);
        }

        private static SelfHostSecurityTokenServiceConfiguration Configuration { get; set; }

        private static void ConfigureSts()
        {
            Configuration = new SelfHostSecurityTokenServiceConfiguration();
            Configuration.CertificateValidationMode = X509CertificateValidationMode.None;
            Configuration.IssuerNameRegistry = new ReturnX509SubjectNameOrRSAIssuerNameRegistry();
            HttpsWSTrust13Address = "https://" + Configuration.BaseAddress + Configuration.HttpsPort + "/";
            HttpWSTrust13Address = "http://" + Configuration.BaseAddress + Configuration.HttpPort + "/";
        }

        private static string HttpsWSTrust13Address { get; set; }

        private static string HttpWSTrust13Address { get; set; }

        private static void SetupWsFedHost()
        {
            Uri fedUri = new Uri("https://" + Configuration.BaseAddress + Configuration.HttpsPort + Constants.WSFedSTS);
            WSFedServiceHost = new WebServiceHost(new WSFederationSecurityTokenService(Configuration), fedUri);
            WSFedServiceHost.AddServiceEndpoint(typeof(IWSFederationSecurityTokenService), new WebHttpBinding(WebHttpSecurityMode.Transport), string.Empty);
        }

        private static void SetupWsTrustHost()
        {

            WSTrustServiceHost = new WSTrustServiceHost(Configuration, new Uri(HttpWSTrust13Address));
            WSTrustServiceHost.Credentials.ServiceCertificate.Certificate = Configuration.ServiceCertificate;
            WSTrustServiceHost.Credentials.UseIdentityConfiguration = true;
            //WSTrustServiceHost.Credentials.IssuedTokenAuthentication.AudienceUriMode = System.IdentityModel.Selectors.AudienceUriMode.Never;
            //WSTrustServiceHost.Credentials.IdentityConfiguration.AudienceRestriction.AudienceMode = System.IdentityModel.Selectors.AudienceUriMode.Never;
            //WSTrustServiceHost.SecurityTokenServiceConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
            //WSTrustServiceHost.Credentials.IssuedTokenAuthentication.CertificateValidationMode = X509CertificateValidationMode.None;
            // sets validation mode for signed tokens received by the SecurityTokenService
            WSTrustServiceHost.SecurityTokenServiceConfiguration.AudienceRestriction.AudienceMode = System.IdentityModel.Selectors.AudienceUriMode.Never;
            WSTrustServiceHost.SecurityTokenServiceConfiguration.SecurityTokenHandlers.AddOrReplace(new SelfHostUserNameSecurityTokenHandler());
            AddWsTrustServiceBindings();
        }

        private static WebServiceHost WSFedServiceHost { get; set; }

        private static WSTrustServiceHost WSTrustServiceHost { get; set; }
    }
}
