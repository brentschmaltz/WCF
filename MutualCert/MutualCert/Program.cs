// ----------------------------------------------------------------------------
// Mutual Cert Binding Example
// ----------------------------------------------------------------------------

using CertUtils;
using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Xml;
using WcfContracts;
using WcfUtilities;

namespace MutualCert
{
    class Program
    {
        static string _authority = "CN=SelfSignedClient";
        static bool _useIdentityModel = true;

        static void Main(string[] args)
        {
            // using self signed certs, we need to set the outbound identity or WCF will fault.
            var baseAddress = "http://127.0.0.1:8080/MutualCert";
            var epi = EndpointIdentity.CreateDnsIdentity("SelfSignedHost");
            var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());

            // message security using Certs over http.
            // no security context, do not negotiate server cert
            var binding = new WSHttpBinding(SecurityMode.Message, false);
            binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.NegotiateServiceCredential = false;

            var customBinding = new CustomBinding(binding);
            BindingUtilities.SetSignatureConfirmation(customBinding, false, false);
            BindingUtilities.SetSecurityHeaderLayout(customBinding, SecurityHeaderLayout.Strict);
            //BindingUtilities.SetMessageProtectionOrder(customBinding, MessageProtectionOrder.EncryptBeforeSign);
            BindingUtilities.SetMaxTimeout(customBinding);
            BindingUtilities.SetReplayDetection(customBinding, false);

            var serviceHost = new ServiceHost(typeof(RequestReplyEncryptAndSign), new Uri(baseAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReplyEncryptAndSign), customBinding, baseAddress);
            if (_useIdentityModel)
            {
                serviceHost.Credentials.UseIdentityConfiguration = true;
                serviceHost.Credentials.IdentityConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
                serviceHost.Credentials.IdentityConfiguration.IssuerNameRegistry = new CustomIssuerNameRegistry(_authority);
            }
            else
            {
                serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            }

            serviceHost.Credentials.ServiceCertificate.SetCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);

            if (serviceHost.Description.Behaviors.Find<ServiceMetadataBehavior>() == null)
                BindingUtilities.AddMexEndpoint(serviceHost, baseAddress, true);

            serviceHost.Open();
            BindingUtilities.DisplayBindingInfoToConsole(serviceHost);

            var cert = CertificateUtilities.GetCertificate(StoreName.My, StoreLocation.LocalMachine, X509FindType.FindBySubjectName, "SelfSignedClient");
            var channelFactory = new ChannelFactory<IRequestReplyEncryptAndSign>(customBinding, epa);
            var customClientCredentials = channelFactory.Credentials;
            customClientCredentials.SupportInteractive = false;
            channelFactory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            channelFactory.Endpoint.EndpointBehaviors.Add(new CustomClientCredentials(customClientCredentials, cert, cert));

            channelFactory.Credentials.ServiceCertificate.SetDefaultCertificate("CN=SelfSignedHost", StoreLocation.LocalMachine, StoreName.My);
            channelFactory.Credentials.ClientCertificate.SetCertificate("CN=SelfSignedClient", StoreLocation.LocalMachine, StoreName.My);
            var srr = channelFactory.CreateChannel();
            try
            {
                var outbound = "SendString";
                Console.WriteLine($"Client sending: '{outbound}'");
                Console.WriteLine($"Client received: '{srr.SendString(outbound)}'");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception: '{e}'");
            }

            Console.WriteLine("Press a key");
            Console.ReadKey();
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

        class CustomClientCredentials : ClientCredentials
        {
            public CustomClientCredentials(CustomClientCredentials other)
                : base(other)
            {
                SigningCertificate = other.SigningCertificate;
            }

            public CustomClientCredentials(ClientCredentials clientCredentials, X509Certificate2 signingCert, X509Certificate2 encryptingCert)
                : base(clientCredentials)
            {
                SigningCertificate = signingCert;
            }

            public override SecurityTokenManager CreateSecurityTokenManager()
            {
                return new CustomClientCredentialsSecurityTokenManager(this);
            }

            protected override ClientCredentials CloneCore()
            {
                return new CustomClientCredentials(this);
            }

            public X509Certificate2 SigningCertificate
            {
                get; set;
            }

            public X509Certificate2 EncryptionCertificate
            {
                get; set;
            }
        }

        class CustomClientCredentialsSecurityTokenManager : ClientCredentialsSecurityTokenManager
        {
            CustomClientCredentials _customClientCredentials;

            public CustomClientCredentialsSecurityTokenManager(CustomClientCredentials customClientCredentials)
                : base(customClientCredentials)
            {
                _customClientCredentials = customClientCredentials;
            }

            public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement requirement)
            {
                return base.CreateSecurityTokenProvider(requirement);
                /*
                SecurityTokenProvider result = null;
                if (requirement.TokenType == SecurityTokenTypes.X509Certificate)
                {
                    MessageDirection direction = requirement.GetProperty<MessageDirection>(ServiceModelSecurityTokenRequirement.MessageDirectionProperty);

                    if (direction == MessageDirection.Output)
                    {
                        if (requirement.KeyUsage == SecurityKeyUsage.Signature)
                            result = new X509SecurityTokenProvider(_customClientCredentials.SigningCertificate);
                        else
                            result = new X509SecurityTokenProvider(_customClientCredentials.EncryptionCertificate);
                    }
                    else
                    {
                        if (requirement.KeyUsage == SecurityKeyUsage.Signature)
                            result = new X509SecurityTokenProvider(_customClientCredentials.SigningCertificate);
                        else
                            result = new X509SecurityTokenProvider(_customClientCredentials.EncryptionCertificate);
                    }
                }
                else
                {
                    result = base.CreateSecurityTokenProvider(requirement);
                }

                return result;
                */
            }

            public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
            {
                var serializer = base.CreateSecurityTokenSerializer(version);

                return new CustomSecurityTokenSerializer(serializer);
            }

            public override SecurityTokenAuthenticator  CreateSecurityTokenAuthenticator(SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver)
            {
                var sta = base.CreateSecurityTokenAuthenticator(tokenRequirement,  out outOfBandTokenResolver);

                outOfBandTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver((new List<SecurityToken>{ new X509SecurityToken(_customClientCredentials.ServiceCertificate.DefaultCertificate)}).AsReadOnly(), true);

                return sta;
            }
        }

        class CustomSecurityTokenSerializer : SecurityTokenSerializer
        {
            private SecurityTokenSerializer _securityTokenSerializer;

            public CustomSecurityTokenSerializer(SecurityTokenSerializer securityTokenSerializer)
            {
                _securityTokenSerializer = securityTokenSerializer;
            }

            protected override bool CanReadKeyIdentifierClauseCore(XmlReader reader)
            {
                throw new NotImplementedException();
            }

            protected override bool CanReadKeyIdentifierCore(XmlReader reader)
            {
                return _securityTokenSerializer.CanReadKeyIdentifier(reader);
            }

            protected override bool CanReadTokenCore(XmlReader reader)
            {
                throw new NotImplementedException();
            }

            protected override bool CanWriteKeyIdentifierClauseCore(SecurityKeyIdentifierClause keyIdentifierClause)
            {
                throw new NotImplementedException();
            }

            protected override bool CanWriteKeyIdentifierCore(SecurityKeyIdentifier keyIdentifier)
            {
                throw new NotImplementedException();
            }

            protected override bool CanWriteTokenCore(SecurityToken token)
            {
                throw new NotImplementedException();
            }

            protected override SecurityKeyIdentifierClause ReadKeyIdentifierClauseCore(XmlReader reader)
            {
                throw new NotImplementedException();
            }

            protected override SecurityKeyIdentifier ReadKeyIdentifierCore(XmlReader reader)
            {
                var ski = _securityTokenSerializer.ReadKeyIdentifier(reader);
                return ski;
            }

            protected override SecurityToken ReadTokenCore(XmlReader reader, SecurityTokenResolver tokenResolver)
            {
                throw new NotImplementedException();
            }

            protected override void WriteKeyIdentifierClauseCore(XmlWriter writer, SecurityKeyIdentifierClause keyIdentifierClause)
            {
                throw new NotImplementedException();
            }

            protected override void WriteKeyIdentifierCore(XmlWriter writer, SecurityKeyIdentifier keyIdentifier)
            {
                _securityTokenSerializer.WriteKeyIdentifier(writer, keyIdentifier);
            }

            protected override void WriteTokenCore(XmlWriter writer, SecurityToken token)
            {
                _securityTokenSerializer.WriteToken(writer, token);
            }
        }
    }
}
