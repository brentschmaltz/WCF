using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using WcfContracts;
using WcfUtilities;

namespace UsernamePasswordValidation
{
    class Program
    {
        static void Main(string[] args)
        {
            var baseAddress = "http://127.0.0.1:8081/UsernamePasswordValidation";
            var epi = EndpointIdentity.CreateDnsIdentity("SelfSignedHost");
            var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());
            var userName = "Alice";
            var password = "$42";

            WSHttpBinding binding = new WSHttpBinding(SecurityMode.Message, false);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.NegotiateServiceCredential = false;
            binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;

            var customBinding = new CustomBinding(binding);
            BindingUtilities.SetMessageProtectionOrder(customBinding, MessageProtectionOrder.EncryptBeforeSign);

            ServiceHost sh = new ServiceHost(typeof(RequestReply), new Uri(baseAddress));
            sh.AddServiceEndpoint(typeof(IRequestReply), binding, baseAddress);
            sh.Credentials.ServiceCertificate.SetCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);
            sh.Credentials.UserNameAuthentication.UserNamePasswordValidationMode = System.ServiceModel.Security.UserNamePasswordValidationMode.Custom;
            sh.Credentials.UserNameAuthentication.CustomUserNamePasswordValidator = new CustomUserNamePasswordValidator(userName, password);
            sh.Open();

            ChannelFactory<IRequestReply> cf = new ChannelFactory<IRequestReply>(binding, epa);
            cf.Credentials.ServiceCertificate.SetDefaultCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);
            cf.Credentials.UserName.UserName = userName;
            cf.Credentials.UserName.Password = password;
            IRequestReply srr = cf.CreateChannel();

            try
            {
                string outbound = "SendString";
                Console.WriteLine("Client sending: '{0}'", outbound);
                string inbound = srr.SendString(outbound);
                Console.WriteLine("Client received: '{0}'", inbound);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: '{0}'", e);
            }

            Console.WriteLine("\nPress any key to close");
            Console.ReadKey();
        }
    }
}
