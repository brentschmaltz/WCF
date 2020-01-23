// ----------------------------------------------------------------------------
// Integrated Windows Auth Example
// ----------------------------------------------------------------------------

using System;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using WcfContracts;
using WcfUtilities;

namespace IntegratedWindowsAuth
{
    class Program
    {
        static void Main(string[] args)
        {
            var baseAddress = "http://127.0.0.1:8080/IntegratedWindowsAuth";
            var binding = new WSHttpBinding(SecurityMode.Transport, false);
            binding.Security.Message.EstablishSecurityContext = true;
            var customBinding = new CustomBinding(binding);
            BindingUtilities.SetSecurityHeaderLayout(customBinding, SecurityHeaderLayout.Strict);
            BindingUtilities.SetMessageProtectionOrder(customBinding, MessageProtectionOrder.EncryptBeforeSign);
            BindingUtilities.SetMaxTimeout(customBinding);
            if (binding.Security.Message.EstablishSecurityContext)
                BindingUtilities.SetSctCookieMode(customBinding, true);

            var sh = new ServiceHost(typeof(RequestReply), new Uri(baseAddress));
            sh.AddServiceEndpoint(typeof(IRequestReply), customBinding, baseAddress);
            sh.Open();

            var cf = new ChannelFactory<IRequestReply>(customBinding, baseAddress);
            var srr = cf.CreateChannel();

            try
            {
                string outbound = "SendString";
                Console.WriteLine($"Client sending: '{outbound}'");
                string inbound = srr.SendString(outbound);
                Console.WriteLine($"Client received: '{inbound}'");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception: '{e}'");
            }

            Console.WriteLine("Press any key to close");
            Console.ReadKey();
        }
    }
}
