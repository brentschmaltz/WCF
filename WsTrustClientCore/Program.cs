using System;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsTrust;

namespace WsTrustClientCore
{
    class Program
    {
        static string _saml11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        static string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
        static string _serviceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";

        static void Main(string[] args)
        {
            // bypasses certificate validation
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);

            try
            {
                string usernameMixed = "trust/13/usernamemixed";
                string windowsMixed = "trust/13/windowsmixed";
                string windowsTransport = "trust/13/windowsTransport";
                string upnIdentity = @"putupnidentityhere";
                string baseAddress = @"https://127.0.0.1:5443/";
                string username = @"bob";
                string password = @"password";

                AppliesTo appliesTo = new AppliesTo(new EndpointReference(_serviceAddress));
                WS2007HttpBinding binding = new WS2007HttpBinding();
                EndpointAddress endpointAddress;
                bool usernameCredentials = true;
                bool mixedMode = false;

                Console.WriteLine($"usernameCredentials: '{usernameCredentials}', mixedMode: '{mixedMode}'.");

                if (usernameCredentials)
                {
                    binding.Security.Message.EstablishSecurityContext = false;
                    binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
                    binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
                    binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                    endpointAddress = new EndpointAddress(baseAddress + usernameMixed);
                }
                else
                {
                    binding.Security.Message.EstablishSecurityContext = false;
                    if (mixedMode)
                    {
                        binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
                        binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
                        binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                        binding.Security.Message.NegotiateServiceCredential = false;
                        endpointAddress = new EndpointAddress(new Uri(baseAddress + windowsMixed));
                    }
                    else
                    {
                        binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Windows;
                        binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
                        binding.Security.Mode = SecurityMode.Transport;
                        endpointAddress = new EndpointAddress(new Uri(baseAddress + windowsTransport));
                    }
                }

                WSTrustChannelFactory trustChannelFactory = new WSTrustChannelFactory(binding, endpointAddress)
                {
                    TrustVersion = WsTrustVersion.Trust13,
                    WsTrustSerializer = new WsTrustSerializer()
                };

                trustChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication { CertificateValidationMode = X509CertificateValidationMode.None };

                SecurityToken token = null;
                if (usernameCredentials)
                {
                    trustChannelFactory.Credentials.UserName.UserName = username;
                    trustChannelFactory.Credentials.UserName.Password = password;
                }
                else
                {
                    trustChannelFactory.Credentials.Windows.ClientCredential = new NetworkCredential();
                }

                WSTrustChannel tokenClient = (WSTrustChannel)trustChannelFactory.CreateChannel(endpointAddress);
                WsTrustRequest rst = new WsTrustRequest("Issue")
                {
                    AppliesTo = appliesTo,
                    TokenType = _saml11,
                    WsTrustVersion = WsTrustVersion.Trust13
                };

                token = tokenClient.Issue(rst);

//                var iar = tokenClient.BeginIssue(rst, AsyncCallback, rst);

//                while (iar.IsCompleted != true)
//                {
//                    UpdateUserInterface();
//                }

//                WsTrustResponse requestSecurityTokenResponse = null;
//                var message = tokenClient.EndIssue(iar, out requestSecurityTokenResponse);

                Console.WriteLine($"SecurityToken: '{token}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception from TrustChannel: '{ex}'.");
            }

            Console.WriteLine($"Press a key to close.");
            Console.ReadKey();
        }

        public static void AsyncCallback(IAsyncResult ar)
        {

        }

        static void UpdateUserInterface()
        {
            // Print a period to indicate that the application
            // is still working on the request.
            Console.Write(".");
        }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Console.WriteLine($"ValidateServerCertificate.\nsslPolicyErrors:'{sslPolicyErrors}'\ncertificate:'{certificate}'.");

            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            return true;
        }
    }
}