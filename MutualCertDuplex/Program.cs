// ----------------------------------------------------------------------------
// MutualCertDuplex Binding Example
// ----------------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using WcfContracts;
using WcfUtilities;

namespace MutualCertDuplex
{
    class Program
    {
        static void Main(string[] args)
        {
            var baseAddress = "http://127.0.0.1:8080/MutualCertDuplex";
            var epi = EndpointIdentity.CreateDnsIdentity("SelfSignedHost");
            var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());
            var customBinding = BindingUtilities.BuildBinding(SecurityBindingElement.CreateMutualCertificateDuplexBindingElement());

            BindingUtilities.SetSecurityHeaderLayout(customBinding, SecurityHeaderLayout.LaxTimestampLast);
            BindingUtilities.SetMessageProtectionOrder(customBinding, MessageProtectionOrder.SignBeforeEncryptAndEncryptSignature);
            BindingUtilities.SetSignatureConfirmation(customBinding, false);
            BindingUtilities.SetMaxTimeout(customBinding);
            BindingUtilities.SetReplayDetection(customBinding, false);
            BindingUtilities.AllowSerializedSigningTokenOnReply(customBinding, true);

            var serviceHost = new ServiceHost(typeof(RequestReplyEncryptAndSign), new Uri(baseAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReplyEncryptAndSign), customBinding, baseAddress);
            serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Credentials.ServiceCertificate.SetCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);

            if (serviceHost.Description.Behaviors.Find<ServiceMetadataBehavior>() == null)
                BindingUtilities.AddMexEndpoint(serviceHost, baseAddress, true);

            serviceHost.Open();

            BindingUtilities.DisplayBindingInfoToConsole(serviceHost);

            var channelFactory = new ChannelFactory<IRequestReplyEncryptAndSign>(customBinding, epa);
            channelFactory.Credentials.ServiceCertificate.SetDefaultCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);
            channelFactory.Credentials.ClientCertificate.SetCertificate("CN=SelfSignedClient", StoreLocation.LocalMachine, StoreName.My);
            channelFactory.Credentials.UseIdentityConfiguration = true;
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
