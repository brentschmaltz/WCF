#define MessageTransform

// ----------------------------------------------------------------------------
// Specifying IssuerSerial in KeyInfo 
// ----------------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using WcfContracts;

// helpful links
// https://blogs.msdn.microsoft.com/distributedservices/2010/06/14/wcf-interoperability-guidelines-1-reference-style-of-a-primary-signing-token-inside-a-response/
// https://stackoverflow.com/questions/9160503/java-client-to-wcf-service-interop-with-mutual-certificate-cannot-resolve-keyi
// https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-3.5/aa967568(v=vs.90)

namespace IssuerSerialKeyInfo
{
    class Program
    {
        static void Main(string[] args)
        {
            var hostName = "SelfHostSts";
            var hostCertDnsName = $"CN={hostName}";
            var clientCertDnsName = "CN=ClientCredential";
            var baseAddress = "http://127.0.0.1:8080/IssuerSerial";
            var serviceBinding = ServiceAsymmetricBinding(
                X509KeyIdentifierClauseType.RawDataKeyIdentifier,
                SecurityTokenInclusionMode.AlwaysToInitiator,
                MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12);

            var serviceHost = new ServiceHost(typeof(RequestReplySign), new Uri(baseAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReplySign), serviceBinding, baseAddress);
            serviceHost.Credentials.ServiceCertificate.SetCertificate(hostCertDnsName, StoreLocation.LocalMachine, StoreName.My);
            // normally one would check cert from request but since the MessageModifier is responsible for intercepting the
            // message and adds embedded 'BinaryBinarySecurityToken' from a certificate found from the IssuerSerial
            // we can assume the caller is trusted
            serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Open();

            SetMaxTimeout(serviceBinding);
            DisplayBindingInfoToConsole(serviceHost);

            // WCF checks outbound identity, since we are sending to "http://127.0.0.1:8080/IssuerSerial", WCF will throw outbound.
            // explicitly setting this DNS address, tells WCF, it's OK
            var epi = EndpointIdentity.CreateDnsIdentity(hostName);
            var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());

            // causes KeyinfoFailure if 'MessageTransform' is not set
            var clientBinding = ClientAsymmetricIssuerSerialBinding(
                X509KeyIdentifierClauseType.IssuerSerial,
                SecurityTokenInclusionMode.AlwaysToInitiator,
                MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12);

            SetMaxTimeout(clientBinding);
            var channelFactory = new ChannelFactory<IRequestReplySign>(clientBinding, epa);
            channelFactory.Credentials.ClientCertificate.SetCertificate(clientCertDnsName, StoreLocation.LocalMachine, StoreName.My);
            channelFactory.Credentials.ServiceCertificate.SetDefaultCertificate(hostCertDnsName, StoreLocation.LocalMachine, StoreName.My);
            var clientChannel = channelFactory.CreateChannel();

            try
            {
                var outbound = "Client SendString";
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

        public static Binding ServiceAsymmetricBinding(
            X509KeyIdentifierClauseType clauseType,
            SecurityTokenInclusionMode inclusionMode,
            MessageSecurityVersion messageSecurityVersion)
        {
            return new CustomBinding(
                new AsymmetricSecurityBindingElement
                (
                    new X509SecurityTokenParameters(clauseType, inclusionMode),
                    new X509SecurityTokenParameters(clauseType, inclusionMode)
                )
                {
                    MessageSecurityVersion = messageSecurityVersion
                },
#if MessageTransform
                new InterceptingBindingElement(),
#endif
                new HttpTransportBindingElement());
        }

        public static Binding ClientAsymmetricIssuerSerialBinding(
            X509KeyIdentifierClauseType clauseType,
            SecurityTokenInclusionMode inclusionMode,
            MessageSecurityVersion messageSecurityVersion)
        {
            return new CustomBinding(
                new AsymmetricSecurityBindingElement
                (
                    new X509SecurityTokenParameters(clauseType, inclusionMode),
                    new X509SecurityTokenParameters(clauseType, inclusionMode)
                )
                {
                    MessageSecurityVersion = messageSecurityVersion
                },
                new HttpTransportBindingElement()
            );
        }

        public static void SetMaxTimeout(System.ServiceModel.Channels.Binding binding)
        {
            binding.CloseTimeout = TimeSpan.MaxValue;
            binding.OpenTimeout = TimeSpan.MaxValue;
            binding.ReceiveTimeout = TimeSpan.MaxValue;
            binding.SendTimeout = TimeSpan.MaxValue;
        }

        public static void DisplayBindingInfoToConsole(ServiceHost serviceHost)
        {
            for (int i = 0; i < serviceHost.ChannelDispatchers.Count; i++)
            {
                if (serviceHost.ChannelDispatchers[i] is ChannelDispatcher channelDispatcher)
                    for (int j = 0; j < channelDispatcher.Endpoints.Count; j++)
                        Console.WriteLine("Listening on " + channelDispatcher.Endpoints[j].EndpointAddress + "...");
            }
        }
    }
}
