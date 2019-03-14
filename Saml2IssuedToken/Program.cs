//------------------------------------------------------------------------------
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
using System.Security.Cryptography;
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

            var cert = CertificateUtilities.GetCertificate(StoreName.My, StoreLocation.LocalMachine, X509FindType.FindByThumbprint, "fefced16e5ee7ad09e2938e82263c7ae6498ce82");

            // Service
            var serviceHost = new ServiceHost(typeof(RequestReply), new Uri(serviceAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReply), binding, serviceAddress);
            serviceHost.Credentials.ServiceCertificate.Certificate = cert;
            serviceHost.Credentials.UseIdentityConfiguration = true;
            serviceHost.Credentials.IdentityConfiguration.AudienceRestriction.AudienceMode = AudienceUriMode.Never;
            serviceHost.Credentials.IdentityConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Credentials.IdentityConfiguration.IssuerNameRegistry = new CustomIssuerNameRegistry(_authority);
            serviceHost.Open();

            // Client
            var clientChannelFactory = new ChannelFactory<IRequestReply>(binding, endpointAddress);
            clientChannelFactory.Credentials.UseIdentityConfiguration = true;
            var client = clientChannelFactory.CreateChannelWithIssuedToken(GetSamlToken(cert, _authority));
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

        static SecurityToken GetSamlToken(X509Certificate2 cert, string issuer)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = CreateSigningCredentials(cert),
                Subject = new ClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, "Bob"),
                    new Claim(ClaimTypes.Email, "Bob@contoso.com"),
                }),
                TokenIssuerName = issuer
            };

            return (new SamlSecurityTokenHandler()).CreateToken(tokenDescriptor);
        }

        static SecurityToken GetSaml2Token(X509Certificate2 cert, string issuer)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = CreateSigningCredentials(cert),
                Subject = new ClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, "Bob"),
                    new Claim(ClaimTypes.Email, "Bob@contoso.com"),
                }),
                TokenIssuerName = issuer
            };

            return (new Saml2SecurityTokenHandler()).CreateToken(tokenDescriptor) as Saml2SecurityToken;
        }

        static SigningCredentials CreateSigningCredentials(X509Certificate2 cert)
        {
            // create a symmetric key
            var symmetricKey = new InMemorySymmetricSecurityKey(Aes.Create().Key, false);
            var x509Key = new X509AsymmetricSecurityKey(cert);
            var encryptedKey = x509Key.EncryptKey(SecurityAlgorithms.RsaV15KeyWrap, symmetricKey.GetSymmetricKey());
            var encryptedKeyIdentifierClause = new EncryptedKeyIdentifierClause(encryptedKey, SecurityAlgorithms.RsaV15KeyWrap, new SecurityKeyIdentifier(new X509ThumbprintKeyIdentifierClause(cert)));
            SecurityKeyIdentifier ski = new SecurityKeyIdentifier(new SecurityKeyIdentifierClause[]
            {
                    encryptedKeyIdentifierClause,
                    new X509RawDataKeyIdentifierClause(cert.RawData)
            });

            // use symmetric key to sign the assertion
            return new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest, ski);
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
