
using System;
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
    /// Defines a class for providing first class properties of STS configuration.
    /// </summary>
    public class SelfHostSecurityTokenServiceConfiguration : SecurityTokenServiceConfiguration
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public SelfHostSecurityTokenServiceConfiguration()
        {

            SecurityTokenHandlers.Add(new JwtSecurityTokenHandler());
            ConfigurationSection = SelfHostSecurityTokenServiceConfigurationSection.StsConfiguration;
            SecurityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.ActAs] = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
            SecurityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.OnBehalfOf] = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
            SigningCredentials = new X509SigningCredentials(new X509Certificate2(ConfigurationSection.MetadataPfxCertificateLocation, ConfigurationSection.MetadataCertificatePassword, X509KeyStorageFlags.PersistKeySet));
            ServiceCertificate = new X509Certificate2(ConfigurationSection.SslPfxLocation, ConfigurationSection.SSLCertificatePassword, X509KeyStorageFlags.PersistKeySet);
            SecurityTokenService = typeof(SelfHostSecurityTokenService);
            TokenIssuerName = ConfigurationSection.IssuerName;
            DefaultTokenType = "JWT";
        }

        public string BaseAddress => ConfigurationSection.BaseAddress;

        private SelfHostSecurityTokenServiceConfigurationSection ConfigurationSection
        {
            get;
            set;
        }

        public string HttpPort => ConfigurationSection.HttpPort;

        public string HttpsPort => ConfigurationSection.HttpsPort;

        /// <summary>
        /// Gets the federation metadata.
        /// </summary>
        /// <returns></returns>
        public XElement GetFederationMetadata()
        {
            var passiveEndpoint = new EndpointReference(ConfigurationSection.BaseAddress + ConfigurationSection.HttpsPort + Constants.WSFedSTSIssue);
            var activeEndpoint = new EndpointReference(ConfigurationSection.BaseAddress + ConfigurationSection.HttpsPort + Constants.WSTrust13);
            var entityDescriptor = new EntityDescriptor(new EntityId(ConfigurationSection.IssuerName));           
            var securityTokenServiceDescriptor = new SecurityTokenServiceDescriptor();
            entityDescriptor.RoleDescriptors.Add(securityTokenServiceDescriptor);

            var signingKey = new KeyDescriptor(SigningCredentials.SigningKeyIdentifier);
            signingKey.Use = KeyType.Signing;
            securityTokenServiceDescriptor.Keys.Add(signingKey);

            for (int i = 0; i < ConfigurationSection.Claims.Count; i++)
            {
                securityTokenServiceDescriptor.ClaimTypesOffered.Add(new DisplayClaim(ConfigurationSection.Claims[i].Type, ConfigurationSection.Claims[i].DisplayName, string.Empty));
            }

            securityTokenServiceDescriptor.PassiveRequestorEndpoints.Add(passiveEndpoint);
            securityTokenServiceDescriptor.SecurityTokenServiceEndpoints.Add(activeEndpoint);


            securityTokenServiceDescriptor.ProtocolsSupported.Add(new Uri(Constants.WSFederationMetadataNamespace));
            securityTokenServiceDescriptor.ProtocolsSupported.Add(new Uri(Constants.WSTrust13Namespace));
            securityTokenServiceDescriptor.ProtocolsSupported.Add(new Uri(Constants.WSTrustFeb2005Namespace));

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
    }
}