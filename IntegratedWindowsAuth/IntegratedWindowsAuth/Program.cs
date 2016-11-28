using System;
using System.ServiceModel;
using System.ServiceModel.Channels;
using WcfContracts;
using WcfUtilities;

namespace IntegratedWindowsAuth
{
    class Program
    {
        static void Main(string[] args)
        {
            var baseAddress = "http://127.0.0.1:8080/IntegratedWindowsAuth";
            var binding = new WSHttpBinding(SecurityMode.Message, false);
            var customBinding = new CustomBinding(binding);
            BindingUtilities.SetSecurityHeaderLayout(customBinding, SecurityHeaderLayout.Lax);
            BindingUtilities.SetMaxTimeout(customBinding);

            var sh = new ServiceHost(typeof(RequestReply), new Uri(baseAddress));
            sh.AddServiceEndpoint(typeof(IRequestReply), customBinding, baseAddress);
            sh.Open();

            var cf = new ChannelFactory<IRequestReply>(customBinding, baseAddress);
            var srr = cf.CreateChannel();

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
        }
    }
}
