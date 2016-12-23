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
            var binding = new WSHttpBinding(SecurityMode.Message, false);
            try
            {
                BindingUtilities.ValidateMessageProtectionOrder(new CustomBinding(binding), MessageProtectionOrder.EncryptBeforeSign);
            }
            catch(Exception ex)
            {
                Console.WriteLine($"BindingUtilities.ValidateMessageProtectionOrder threw: {ex}.");
            }

            Console.WriteLine("Press any key to close");
            Console.ReadKey();
        }
    }
}

