//------------------------------------------------------------------------------
//
// Copyright (c) Brent Schmaltz
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
using System.IdentityModel.Configuration;
using System.IdentityModel.Metadata;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace SelfHostSTS
{
    /// <summary>
    /// Configures the STS
    /// </summary>
    public class SelfHostSecurityTokenServiceConfiguration : SecurityTokenServiceConfiguration
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public SelfHostSecurityTokenServiceConfiguration()
        {
            RelyingPartyCertificate = new X509Certificate2("Certs\\RelyingParty.cer");
            SecurityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.ActAs] = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
            SecurityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.OnBehalfOf] = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
            SigningCredentials = new X509SigningCredentials(new X509Certificate2("Certs\\SelfHostSts.pfx", "SelfHostSts", X509KeyStorageFlags.EphemeralKeySet));
            ServiceCertificate = new X509Certificate2("Certs\\SelfHostSts.pfx", "SelfHostSts", X509KeyStorageFlags.EphemeralKeySet);
            SecurityTokenService = typeof(SelfHostSecurityTokenService);
            TokenIssuerName = "SelfHostSts";
        }

        public string BaseAddress => "127.0.0.1:";

        IList<DisplayClaim> Claims
        {
            get
            {
                return new List<DisplayClaim>();
            }
        }

        /// <summary>
        /// Gets the federation metadata.
        /// </summary>
        /// <returns></returns>
        public XElement GetFederationMetadata()
        {
            var passiveEndpoint = new EndpointReference(BaseAddress + HttpsPort + Constants.WSFedSTSIssue);
            var activeEndpoint = new EndpointReference(BaseAddress + HttpsPort + Constants.WSTrust13);
            var entityDescriptor = new EntityDescriptor(new EntityId(TokenIssuerName));
            var securityTokenServiceDescriptor = new SecurityTokenServiceDescriptor();
            entityDescriptor.RoleDescriptors.Add(securityTokenServiceDescriptor);

            var signingKey = new KeyDescriptor(SigningCredentials.SigningKeyIdentifier);
            signingKey.Use = KeyType.Signing;
            securityTokenServiceDescriptor.Keys.Add(signingKey);

            foreach (var claim in Claims)
                securityTokenServiceDescriptor.ClaimTypesOffered.Add(new DisplayClaim(claim.ClaimType, claim.DisplayValue, string.Empty));

            securityTokenServiceDescriptor.PassiveRequestorEndpoints.Add(passiveEndpoint);
            securityTokenServiceDescriptor.ProtocolsSupported.Add(new Uri(Constants.WSFederationMetadataNamespace));
            securityTokenServiceDescriptor.ProtocolsSupported.Add(new Uri(Constants.WSTrust13Namespace));
            securityTokenServiceDescriptor.ProtocolsSupported.Add(new Uri(Constants.WSTrustFeb2005Namespace));
            securityTokenServiceDescriptor.SecurityTokenServiceEndpoints.Add(activeEndpoint);
            entityDescriptor.SigningCredentials = SigningCredentials;

            var serializer = new MetadataSerializer();
            XElement federationMetadata = null;

            using (var stream = new MemoryStream())
            {
                serializer.WriteMetadata(stream, entityDescriptor);
                stream.Flush();
                stream.Seek(0, SeekOrigin.Begin);

                var xmlReader = XmlTextReader.Create(stream);
                federationMetadata = XElement.Load(xmlReader);
            }

            return federationMetadata;
        }

        public string HttpPort => "8080";

        public string HttpsPort => "5443";

        public X509Certificate2 RelyingPartyCertificate { get; }
    }
}