using System;
using System.Configuration;
using System.Globalization;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel.Web;
using WCFSecurityUtilities;

namespace SelfHostSTS
{
    class Program
    {
        private static string _endpointNameMessageIWA = "messageIWA";
        private static string _endpointTransportIWA = "transportIWA";
        private static string _endpointNameMessageUserName = "messageUserName";
        private static string _endpointNameTransportIssuerSaml20 = "transportIssueSaml20";
        private static string _endpointNameTransportIssuerSaml = "transportIssueSaml";
        private static string _endpointNameTransportUserName = "transportUserName";

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
            AddBinding(WSTrustServiceHost, typeof(WS2007HttpBinding), SecurityMode.Message, false, HttpWSTrust13Address, _endpointNameMessageUserName, MessageCredentialType.UserName);
            AddBinding(WSTrustServiceHost, typeof(WS2007HttpBinding), SecurityMode.Transport, false, HttpsWSTrust13Address, _endpointTransportIWA, MessageCredentialType.Windows);
        }

        private static SelfHostSecurityTokenServiceConfiguration Configuration { get; set; }

        private static void ConfigureSts()
        {
            // netsh>http add sslcert ipport=127.0.0.1:5443 certhash=9b74cb2f320f7aafc156e1252270b1dc01ef40d0 appid={98C671E2-050A-4D66-97DA-8C7AB80AFAC5}
            // netsh>http add sslcert ipport=127.0.0.1:5443 certhash=36622f03317f8ccf4ae5aa812255c6dd7cb13eff appid={98C671E2-050A-4D66-97DA-8C7AB80AFAC5}
            // netsh>http add sslcert ipport=127.0.0.1:5443 certhash=cfb894905fb847d8da1d3df6886ebe22b3b533d8 appid={98C671E2-050A-4D66-97DA-8C7AB80AFAC5}
            // netsh>http add sslcert ipport=127.0.0.1:5443 certhash=2aa8722c73e8c88409203411b1ac80af8a8deb3a appid={98C671E2-050A-4D66-97DA-8C7AB80AFAC5}

            Configuration = new SelfHostSecurityTokenServiceConfiguration();
            Configuration.CertificateValidationMode = X509CertificateValidationMode.None;
            Configuration.IssuerNameRegistry = new ReturnX509SubjectNameOrRSAIssuerNameRegistry();
            HttpsWSTrust13Address = "https://" + Configuration.BaseAddress + Configuration.HttpsPort + Constants.WSTrust13;
            HttpWSTrust13Address = "http://" + Configuration.BaseAddress + Configuration.HttpPort + Constants.WSTrust13;
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
