// ----------------------------------------------------------------------------
// Specifying IssuerSerial in KeyInfo 
// ----------------------------------------------------------------------------

using System;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using WcfContracts;
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
            var binding = new WSHttpBinding(SecurityMode.Message, false);

            binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            binding.Security.Message.EstablishSecurityContext = false;

            var serviceHost = new ServiceHost(typeof(RequestReplySign), new Uri(baseAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReplySign), binding, baseAddress);
            serviceHost.Credentials.ServiceCertificate.SetCertificate(certDnsName, StoreLocation.LocalMachine, StoreName.My);
            
            // since we need to check the client cert, use a CustomX509CertificateValidator
            serviceHost.Credentials.ClientCertificate.Authentication.CustomCertificateValidator = new CustomX509CertificateValidator();
            serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.Custom;

            if (serviceHost.Description.Behaviors.Find<ServiceMetadataBehavior>() == null)
                BindingUtilities.AddMexEndpoint(serviceHost, baseAddress, true);

            serviceHost.Open();

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
    }

    public class CustomX509CertificateValidator : X509CertificateValidator
    {
        public override void Validate(X509Certificate2 certificate)
        {
            // put in code to check cert
        }
    }
}
