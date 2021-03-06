﻿//------------------------------------------------------------------------------
//
// Copyright (c) Brent Schmaltz.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using WcfUtilities;

// setup http.sys with cert that has DNS "CN=localhost" and thumbprint == 5008e9b6f4995c472a67c16cc18dad36acf4be38
// httpcfg.exe set ssl -i 127.0.0.1:443 -h 5008e9b6f4995c472a67c16cc18dad36acf4be38
// netsh http add sslcert ipport=127.0.0.1:443 certhash=5008e9b6f4995c472a67c16cc18dad36acf4be38 appid={00112233-4455-6677-8899-AABBCCDDEEFF}

namespace Saml2IssuedToken
{
    class Program
    {
        //static string _authority = "http://127.0.0.1:8080/WsTrust13/messageUserName";
        static string _authority = "https://fs.msidlab8.com/adfs/services/trust/13/usernamemixed";
        //static string _authority = "https://fs.msidlab8.com/adfs/services/trust/13/windowstransport";
        //static string _authority = "http://fs.msidlab4.com/adfs/services/trust/13/windows";
        static string _saml11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        static string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
        static string _serviceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";

        //static string _authority = "https://msft.sts.microsoft.com/adfs/services/trust/2005/windowstransport";
        //static string _authority = "https://msft.sts.microsoft.com/adfs/services/trust/13/windowstransport";
        //metadata https://fs.msidlab8.com/federationmetadata/2007-06/federationmetadata.xml 


        static void Main(string[] args)
        {
            // bypasses certificate validation
            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;

            // federation binding
            // this got through SecurityHeaderProcessing
            var authorityBinding = AuthorityBinding();
            var serviceBinding = ServiceBinding(authorityBinding);

            // service host
            var cert = CertificateUtilities.GetCertificate(StoreName.My, StoreLocation.LocalMachine, X509FindType.FindBySubjectName, "SelfHostSts");
            var serviceHost = new ServiceHost(typeof(RequestReply), new Uri(_serviceAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReply), serviceBinding, _serviceAddress);
            serviceHost.Credentials.ServiceCertificate.Certificate = cert;
            serviceHost.Credentials.UseIdentityConfiguration = true;
            serviceHost.Credentials.IdentityConfiguration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(_serviceAddress));
            serviceHost.Credentials.IdentityConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Credentials.IdentityConfiguration.IssuerNameRegistry = new CustomIssuerNameRegistry(_authority);
            serviceHost.Open();

            bool runClient = true;

            // client factory
            if (runClient)
            {
                var channelFactory = new ChannelFactory<IRequestReply>(serviceBinding, new EndpointAddress(new Uri(_serviceAddress), EndpointIdentity.CreateX509CertificateIdentity(cert), new AddressHeaderCollection()));
                channelFactory.Credentials.UseIdentityConfiguration = true;
                channelFactory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
                channelFactory.Credentials.UserName.UserName = "msidlab8";
                channelFactory.Credentials.UserName.Password = "Baii#251";
                var requestChannel = channelFactory.CreateChannel();
                try
                {
                    var outboundMessage = "Hello";
                    Console.WriteLine($"Channel sending:'{outboundMessage}'.");
                    Console.WriteLine($"Channel received: '{requestChannel.SendString(outboundMessage)}'.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Caught Exception => '{ex}'.");
                }
            }

            Console.WriteLine("Press any key to close, ServiceHost listening.");
            Console.ReadKey();
        }

        public static Binding AuthorityBinding()
        {
            var authorityBinding = new WS2007HttpBinding(SecurityMode.TransportWithMessageCredential);
            authorityBinding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            authorityBinding.Security.Message.EstablishSecurityContext = false;
            SetMaxTimeout(authorityBinding);

            return authorityBinding;
        }

        public static Binding ServiceBinding(Binding authorityBinding)
        {
            var serviceBinding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            serviceBinding.Security.Message.IssuedTokenType = _saml20;
            serviceBinding.Security.Message.IssuerAddress = new EndpointAddress(_authority);
            serviceBinding.Security.Message.IssuerBinding = authorityBinding;
            serviceBinding.Security.Message.IssuedKeyType = SecurityKeyType.SymmetricKey;
            serviceBinding.Security.Message.EstablishSecurityContext = false;
            SetMaxTimeout(serviceBinding);

            return serviceBinding;
        }

        public static void SetMaxTimeout(Binding binding)
        {
            binding.CloseTimeout = TimeSpan.MaxValue;
            binding.OpenTimeout = TimeSpan.MaxValue;
            binding.ReceiveTimeout = TimeSpan.MaxValue;
            binding.SendTimeout = TimeSpan.MaxValue;
        }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine($"ValidateServerCertificate.\nsslPolicyErrors:\n'{sslPolicyErrors}'\ncertificate:\n'{certificate}'.");
            return true;
        }
    }

    class CustomIssuerNameRegistry : IssuerNameRegistry
    {
        string _issuer;
        public CustomIssuerNameRegistry(string issuer)
        {
            _issuer = issuer;
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            return _issuer;
        }
    }

    class CustomIdentityVerifier : IdentityVerifier
    {
        public override bool CheckAccess(EndpointIdentity identity, AuthorizationContext authContext)
        {
            return true;
        }

        public override bool TryGetIdentity(EndpointAddress reference, out EndpointIdentity identity)
        {
            return IdentityVerifier.CreateDefault().TryGetIdentity(reference, out identity);
        }
    }

    [ServiceContract]
    interface IRequestReply
    {
        [OperationContract(Name ="SendString")]
        string SendString(string message);
    }

    [ServiceBehavior]
    class RequestReply : IRequestReply
    {
        [OperationBehavior]
        public string SendString(string message)
        {
            string outbound = string.Format($"Service received: '{message}'.");
            Console.WriteLine($"Service received: '{message}'.");
            Console.WriteLine($"Service returning: '{outbound}'.");
            return outbound;
        }
    }
}
