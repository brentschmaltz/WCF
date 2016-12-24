// ----------------------------------------------------------------------------
// Integrated Windows Auth Example
// ----------------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using WcfContracts;
using WcfUtilities;

namespace MessageProtectionOrderExample
{
    class Program
    {
        static void Main(string[] args)
        {
            var baseAddress = "http://127.0.0.1:8080/MessageProtectionOrderExample/";
            var epi = EndpointIdentity.CreateDnsIdentity("SelfSignedHost");
            var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());
            var certificateBinding = new WSHttpBinding(SecurityMode.Message);
            certificateBinding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;

            var integratedWindowsAuthBinding = new WSHttpBinding(SecurityMode.Message);

            var serviceHost = new ServiceHost(typeof(RequestReply), new Uri(baseAddress));

            serviceHost.AddServiceEndpoint(typeof(IRequestReply), certificateBinding, baseAddress + "certificateBinding");
            serviceHost.AddServiceEndpoint(typeof(IRequestReply), integratedWindowsAuthBinding, baseAddress + "integratedWindowsAuthBinding");
            serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Credentials.ServiceCertificate.SetCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);
            serviceHost.Open();
            BindingUtilities.DisplayBindingInfoToConsole(serviceHost);

            // check serviceHost
            try
            {
                BindingUtilities.ValidateMessageProtectionOrder(serviceHost, MessageProtectionOrder.EncryptBeforeSign);
                Console.WriteLine($"All ServiceHost Bindings have MessageProtectionOrder of: '{MessageProtectionOrder.EncryptBeforeSign}'.");
            }
            catch(Exception ex)
            {
                Console.WriteLine($"BindingUtilities.ValidateMessageProtectionOrder threw: {ex}.");
            }
            serviceHost.Close();

            // BindingUtilities returns customBinding
            var certificateCustomBinding = BindingUtilities.SetMessageProtectionOrder(certificateBinding, MessageProtectionOrder.EncryptBeforeSign);
            var integratedWindowsAuthCustomBinding = BindingUtilities.SetMessageProtectionOrder(integratedWindowsAuthBinding, MessageProtectionOrder.EncryptBeforeSign);

            // create ServiceHost first modify each binding
            serviceHost = new ServiceHost(typeof(RequestReply), new Uri(baseAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReply), certificateCustomBinding, baseAddress + "certificateBinding");
            serviceHost.AddServiceEndpoint(typeof(IRequestReply), integratedWindowsAuthCustomBinding, baseAddress + "integratedWindowsAuthBinding");
            serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Credentials.ServiceCertificate.SetCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);
            serviceHost.Open();
            BindingUtilities.DisplayBindingInfoToConsole(serviceHost);

            // check serviceHost
            try
            {
                BindingUtilities.ValidateMessageProtectionOrder(serviceHost, MessageProtectionOrder.EncryptBeforeSign);
                Console.WriteLine($"All ServiceHost Bindings have MessageProtectionOrder of: '{MessageProtectionOrder.EncryptBeforeSign}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"BindingUtilities.ValidateMessageProtectionOrder threw: {ex}.");
            }

            Console.WriteLine("Press any key to close");
            Console.ReadKey();
        }
    }
}

