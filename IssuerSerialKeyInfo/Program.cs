// ----------------------------------------------------------------------------
// Specifying IssuerSerial in KeyInfo 
// ----------------------------------------------------------------------------

using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using WcfContracts;
using WCFSecurityUtilities;
using WcfUtilities;

namespace IssuerSerialKeyInfo
{
    class Program
    {
        static void Main(string[] args)
        {
            var hostName = "SelfHostSts";
            var certDnsName = $"CN={hostName}";
            var baseAddress = "http://127.0.0.1:8080/IssuerSerial";
            var binding = AsymmetricMutualCertIssuerSerial();

            //var binding = new WSHttpBinding(SecurityMode.Message, false);

            //binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            //binding.Security.Message.EstablishSecurityContext = false;

            var serviceHost = new ServiceHost(typeof(RequestReplySign), new Uri(baseAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReplySign), binding, baseAddress);
            serviceHost.Credentials.ServiceCertificate.SetCertificate(certDnsName, StoreLocation.LocalMachine, StoreName.My);
            serviceHost.Credentials.IdentityConfiguration = new System.IdentityModel.Configuration.IdentityConfiguration
            {
                IssuerTokenResolver = new CustomSecurityTokenResolver(),
                ServiceTokenResolver = new CustomSecurityTokenResolver()
            };

            // since we need to check the client cert, use a CustomX509CertificateValidator
            serviceHost.Credentials.ClientCertificate.Authentication.CustomCertificateValidator = new CustomX509CertificateValidator();
            serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.Custom;
            serviceHost.Credentials.ClientCertificate.SetCertificate(certDnsName, StoreLocation.LocalMachine, StoreName.My);
            if (serviceHost.Description.Behaviors.Find<ServiceMetadataBehavior>() == null)
                BindingUtilities.AddMexEndpoint(serviceHost, baseAddress, true);

         //   PlugableServiceCredentials psc = new PlugableServiceCredentials(serviceHost);
         //   psc.SetSecurityTokenAuthenticator(SecurityTokenTypes.X509Certificate, new CustomSecurityTokenAuthenticator(), new CustomSecurityTokenResolver());
         //   psc.SetSecuriyTokenProvider(SecurityTokenTypes.X509Certificate, new CustomSecurityTokenProvider());

            serviceHost.Open();

            BindingUtilities.SetMaxTimeout(binding);
            BindingUtilities.DisplayBindingInfoToConsole(serviceHost);

            // WCF checks outbound identity, since we are sending to "http://127.0.0.1:8080/IssuerSerial", WCF will throw outbound.
            // explicitly setting this DNS address, tells WCF, it's OK
            var epi = EndpointIdentity.CreateDnsIdentity(hostName);
            var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());
            var channelFactory = new ChannelFactory<IRequestReplySign>(binding, epa);

            // since we are negotiating the server credential use a CustomX509CertificateValidator to validate the cert
            channelFactory.Credentials.ClientCertificate.SetCertificate(certDnsName, StoreLocation.LocalMachine, StoreName.My);
            channelFactory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.Custom;
            channelFactory.Credentials.ServiceCertificate.Authentication.CustomCertificateValidator = new CustomX509CertificateValidator();
            channelFactory.Credentials.ServiceCertificate.SetDefaultCertificate(certDnsName, StoreLocation.LocalMachine, StoreName.My);
            var clientChannel = channelFactory.CreateChannel();

            try
            {
                var outbound = "SendString";
                Console.WriteLine($"Client sending: '{outbound}'");
                Console.WriteLine($"Client received: '{clientChannel.SendString(outbound)}'");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception: '{e}'");
            }

            Console.WriteLine("Press a key");
            Console.ReadKey();
        }

        public static Binding AsymmetricMutualCertIssuerSerial()
        {
            // returns AsymmetricSecurityBindingElement as WSecurity == 1.0
            var sb10 = SecurityBindingElement.CreateMutualCertificateBindingElement(MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10);

            // returns SymmetricSecurityBindingElement as WSecurity != 1.0, this is unexpected
            var sb11 = SecurityBindingElement.CreateMutualCertificateBindingElement(MessageSecurityVersion.WSSecurity11WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11);

            // returns AsymmetricSecurityBindingElement even though WSSecurity == 1.1
            var sb11D = SecurityBindingElement.CreateMutualCertificateDuplexBindingElement(MessageSecurityVersion.WSSecurity11WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11);

            return new CustomBinding(
                new AsymmetricSecurityBindingElement(
                    new X509SecurityTokenParameters(X509KeyIdentifierClauseType.IssuerSerial)
                    {
                        InclusionMode = SecurityTokenInclusionMode.AlwaysToInitiator,
                        X509ReferenceStyle = X509KeyIdentifierClauseType.IssuerSerial
                    },
                    new X509SecurityTokenParameters(X509KeyIdentifierClauseType.IssuerSerial)
                    {
                        InclusionMode = SecurityTokenInclusionMode.AlwaysToInitiator,
                        X509ReferenceStyle = X509KeyIdentifierClauseType.IssuerSerial
                    }
                ),
                new HttpTransportBindingElement()
            );
        }
    }

    public class CustomSecurityTokenResolver : SecurityTokenResolver
    {
        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            throw new NotImplementedException();
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifier keyIdentifier, out SecurityToken token)
        {
            throw new NotImplementedException();
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token)
        {
            throw new NotImplementedException();
        }
    }

    public class CustomX509CertificateValidator : X509CertificateValidator
    {
        public override void Validate(X509Certificate2 certificate)
        {
            // put in code to check cert
        }
    }
}
