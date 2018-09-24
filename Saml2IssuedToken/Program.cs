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
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using WcfKeys;

// setup http.sys with cert that has DNS "CN=localhost" and thumbprint == 5008e9b6f4995c472a67c16cc18dad36acf4be38
// httpcfg.exe set ssl -i 127.0.0.1:443 -h 5008e9b6f4995c472a67c16cc18dad36acf4be38
// netsh http add sslcert ipport=127.0.0.1:443 certhash=5008e9b6f4995c472a67c16cc18dad36acf4be38 appid={00112233-4455-6677-8899-AABBCCDDEEFF}

namespace Saml2IssuedToken
{
    class Program
    {
        static string serviceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";
        static string _authority = "https://authority.sts.com";

        static void Main(string[] args)
        {
            // bypasses that certificate is not really trusted
            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;

            var binding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            binding.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;
            binding.Security.Message.EstablishSecurityContext = false;
            var endpointAddress = new EndpointAddress(serviceAddress);
            SetMaxTimeout(binding);

            // Service
            var serviceHost = new ServiceHost(typeof(RequestReply), new Uri(serviceAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReply), binding, serviceAddress);
            serviceHost.Credentials.ServiceCertificate.SetCertificate("CN=localhost", StoreLocation.LocalMachine, StoreName.My);
            serviceHost.Credentials.UseIdentityConfiguration = true;
            serviceHost.Credentials.IdentityConfiguration.AudienceRestriction.AudienceMode = AudienceUriMode.Never;
            serviceHost.Credentials.IdentityConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Credentials.IdentityConfiguration.IssuerNameRegistry = new CustomIssuerNameRegistry(_authority);
            serviceHost.Open();

            // Client
            var clientChannelFactory = new ChannelFactory<IRequestReply>(binding, endpointAddress);
            clientChannelFactory.Credentials.UseIdentityConfiguration = true;
            var client = clientChannelFactory.CreateChannelWithIssuedToken(GetSaml2Token(_authority));
            try
            {
                Console.WriteLine(string.Format(@"Client received from server: '{0}'", client.SendString("hello from client.")));
            }
            catch (Exception e)
            {
                Console.WriteLine("Caught Exception => '{0}'", e.ToString());
            }

            Console.WriteLine("Press any key to close.");
            Console.ReadKey();
        }

        static Saml2SecurityToken GetSaml2Token(string issuer)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, issuer, issuer),
                new Claim(ClaimTypes.NameIdentifier, "Bob", ClaimValueTypes.String, issuer, issuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, issuer, issuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, issuer, issuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, issuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, issuer, issuer),
                new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, issuer),
                new Claim(ClaimTypes.StreetAddress, "123AnyWhereStreet/r/nSomeTown/r/nUSA", ClaimValueTypes.String, issuer, issuer),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, issuer, issuer),
            };

            var subject = new ClaimsIdentity(claims);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = new X509SigningCredentials(KeyMaterial.CertSelfSigned1024_SHA256),
                Subject = subject,
                TokenIssuerName = issuer
            };
            var tokenHandler = new Saml2SecurityTokenHandler();
            return tokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;
        }

        public static void SetMaxTimeout(Binding binding)
        {
            binding.CloseTimeout = TimeSpan.MaxValue;
            binding.OpenTimeout = TimeSpan.MaxValue;
            binding.ReceiveTimeout = TimeSpan.MaxValue;
            binding.SendTimeout = TimeSpan.MaxValue;
        }

        static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
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

    [ServiceContract]
    interface IRequestReply
    {
        [OperationContract()]
        string SendString(string message);
    }

    [ServiceBehavior]
    class RequestReply : IRequestReply
    {
        [OperationBehavior]
        public string SendString(string message)
        {
            string outbound = string.Format("Service received: {0}", message);

            Console.WriteLine("Service received: '{0}'", message);
            Console.WriteLine("Service sending: '{0}'", outbound);

            return outbound;
        }
    }
}
