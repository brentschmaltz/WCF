// ----------------------------------------------------------------------------
// Mutual Cert Binding Example
// ----------------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using WcfContracts;
using WcfUtilities;

namespace MutualCert
{
    class Program
    {
        static void Main(string[] args)
        {
            // using self signed certs, we need to set the outbound identity or WCF will fault.
            var baseAddress = "http://127.0.0.1:8080/MutualCert";
            var epi = EndpointIdentity.CreateDnsIdentity("SelfSignedHost");
            var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());

            // message security using Certs over http.
            // no security context, do not negotiate server cert
            var binding = new WSHttpBinding(SecurityMode.Message, false);
            binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.NegotiateServiceCredential = false;

            var customBinding = new CustomBinding(binding);
            BindingUtilities.SetSecurityHeaderLayout(customBinding, SecurityHeaderLayout.Strict);
            BindingUtilities.SetMessageProtectionOrder(customBinding, MessageProtectionOrder.EncryptBeforeSign);
            BindingUtilities.SetMaxTimeout(customBinding);
            BindingUtilities.SetReplayDetection(customBinding, false);

            var serviceHost = new ServiceHost(typeof(RequestReplyEncryptAndSign), new Uri(baseAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReplyEncryptAndSign), customBinding, baseAddress);
            serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.ChainTrust;
            serviceHost.Credentials.ServiceCertificate.SetCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);

            if (serviceHost.Description.Behaviors.Find<ServiceMetadataBehavior>() == null)
                BindingUtilities.AddMexEndpoint(serviceHost, baseAddress, true);

            serviceHost.Open();
            BindingUtilities.DisplayBindingInfoToConsole(serviceHost);

            var channelFactory = new ChannelFactory<IRequestReplyEncryptAndSign>(customBinding, epa);
            channelFactory.Credentials.ServiceCertificate.SetDefaultCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);
            channelFactory.Credentials.ClientCertificate.SetCertificate("CN=SelfSignedClient", StoreLocation.LocalMachine, StoreName.My);
            var srr = channelFactory.CreateChannel();
            try
            {
                var outbound = "SendString";
                Console.WriteLine($"Client sending: '{outbound}'");
                Console.WriteLine($"Client received: '{srr.SendString(outbound)}'");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception: '{e}'");
            }

            Console.WriteLine("Press a key");
            Console.ReadKey();
        }
    }
}
