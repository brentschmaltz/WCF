
using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;

namespace WCFSecurityUtilities
{
    public class TokenBuilder
    {
        public static GenericXmlSecurityToken BuildGenericXmlSecurityTokenUsingEnryptedAssertion(Saml2SecurityToken saml2SecurityToken, SymmetricSecurityKey symmetricSecurityKey)
        {
            var rootElement = GetEncryptedAssertion(saml2SecurityToken);

            return new GenericXmlSecurityToken(
                rootElement,
                new BinarySecretSecurityToken(symmetricSecurityKey.GetSymmetricKey()),
                new DateTime(1900, 12, 1, 0, 0, 0),
                new DateTime(2100, 12, 1, 0, 0, 0),
                saml2SecurityToken.CreateKeyIdentifierClause<SamlAssertionKeyIdentifierClause>(),
                saml2SecurityToken.CreateKeyIdentifierClause<SamlAssertionKeyIdentifierClause>(),
                null);
        }

        public static GenericXmlSecurityToken BuildGenericXmlSecurityTokenUsingEnryptedData(Saml2SecurityToken saml2SecurityToken, SymmetricSecurityKey symmetricSecurityKey)
        {
            var rootElement = GetEncryptedData(saml2SecurityToken);

            return new GenericXmlSecurityToken(
                rootElement,
                new BinarySecretSecurityToken(symmetricSecurityKey.GetSymmetricKey()),
                new DateTime(1900, 12, 1, 0, 0, 0),
                new DateTime(2100, 12, 1, 0, 0, 0),
                saml2SecurityToken.CreateKeyIdentifierClause<Saml2AssertionKeyIdentifierClause>(),
                saml2SecurityToken.CreateKeyIdentifierClause<Saml2AssertionKeyIdentifierClause>(),
                null);
        }

        public static GenericXmlSecurityToken BuildGenericXmlSecurityToken(EncryptedSecurityToken encryptedSecurityToken, SymmetricSecurityKey symmetricSecurityKey)
        {
            var rootElement = GetRootElement(encryptedSecurityToken);

            return new GenericXmlSecurityToken(
                rootElement,
                new BinarySecretSecurityToken(symmetricSecurityKey.GetSymmetricKey()),
                new DateTime(1900, 12, 1, 0, 0, 0),
                new DateTime(2100, 12, 1, 0, 0, 0),
                encryptedSecurityToken.CreateKeyIdentifierClause<SamlAssertionKeyIdentifierClause>(),
                encryptedSecurityToken.CreateKeyIdentifierClause<SamlAssertionKeyIdentifierClause>(),
                null);
        }


        public static XmlElement GetEncryptedAssertion(Saml2SecurityToken saml2SecurityToken)
        {
            return GetRootElement(saml2SecurityToken);
        }

        public static XmlElement GetEncryptedData(Saml2SecurityToken saml2SecurityToken)
        {
            var rootElement = GetRootElement(saml2SecurityToken);
            return rootElement.FirstChild as XmlElement;
        }

        public static XmlElement GetRootElement(Saml2SecurityToken saml2SecurityToken)
        {
            return GetRootElement(saml2SecurityToken, new Saml2SecurityTokenHandler());
        }

        public static XmlElement GetRootElement(EncryptedSecurityToken encryptedSecurityToken)
        {
            var handlerCollection = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
            var ms = new MemoryStream();
            var xmlWriter = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8);
            handlerCollection.WriteToken(xmlWriter, encryptedSecurityToken);
            xmlWriter.Flush();
            var tokenString = Encoding.UTF8.GetString(ms.ToArray());
            var xmlReader = XmlDictionaryReader.CreateTextReader(ms.ToArray(), XmlDictionaryReaderQuotas.Max);
            var doc = new XmlDocument();
            return doc.ReadNode(xmlReader) as XmlElement;
        }

        private static XmlElement GetRootElement(SecurityToken securityToken, SecurityTokenHandler securityTokenHandler)
        {
            var ms = new MemoryStream();
            var xmlWriter = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8);
            securityTokenHandler.WriteToken(xmlWriter, securityToken);
            xmlWriter.Flush();
            var tokenString = Encoding.UTF8.GetString(ms.ToArray());
            var xmlReader = XmlDictionaryReader.CreateTextReader(ms.ToArray(), XmlDictionaryReaderQuotas.Max);
            var doc = new XmlDocument();
            return doc.ReadNode(xmlReader) as XmlElement;
        }

        public static Saml2SecurityToken BuildSaml2SecurityToken(ClaimsIdentity subject, string appliesTo, X509Certificate2 signingCert, X509Certificate2 encryptingCert, SymmetricSecurityKey proofKey)
        {
            if (string.IsNullOrEmpty(appliesTo))
                throw new ArgumentNullException(nameof(appliesTo));

            if (signingCert == null)
                throw new ArgumentNullException(nameof(signingCert));

            if (encryptingCert == null)
                throw new ArgumentNullException(nameof(encryptingCert));

            if (proofKey == null)
                throw new ArgumentNullException(nameof(proofKey));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                AppliesToAddress = "https://localhost.com",
                Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1)),
                Proof = new SymmetricProofDescriptor(proofKey.GetSymmetricKey(), new X509EncryptingCredentials(encryptingCert)),
                SigningCredentials = new X509SigningCredentials(signingCert),
                EncryptingCredentials = new EncryptedKeyEncryptingCredentials(encryptingCert),
                Subject = subject,
                TokenIssuerName = Issuer
            };

            var tokenHandler = new Saml2SecurityTokenHandler();
            var encryptedtoken = tokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;
            return new Saml2SecurityToken(encryptedtoken.Assertion, (new List<SecurityKey> { proofKey }).AsReadOnly(), new X509SecurityToken(signingCert));
        }

        public static EncryptedSecurityToken BuildSamlSecurityToken(ClaimsIdentity subject, string appliesTo, X509Certificate2 signingCert, X509Certificate2 encryptingCert, SymmetricSecurityKey proofKey)
        {

            if (string.IsNullOrEmpty(appliesTo))
                throw new ArgumentNullException(nameof(appliesTo));

            if (signingCert == null)
                throw new ArgumentNullException(nameof(signingCert));

            if (encryptingCert == null)
                throw new ArgumentNullException(nameof(encryptingCert));

            if (proofKey == null)
                throw new ArgumentNullException(nameof(proofKey));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                AppliesToAddress = "https://localhost.com",
                Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1)),
                Proof = new SymmetricProofDescriptor(proofKey.GetSymmetricKey(), new X509EncryptingCredentials(encryptingCert)),
                SigningCredentials = new X509SigningCredentials(signingCert),
                EncryptingCredentials = new EncryptedKeyEncryptingCredentials(encryptingCert),
                Subject = subject,
                TokenIssuerName = Issuer
            };

            var tokenHandler = new SamlSecurityTokenHandler();
            var encryptedToken = tokenHandler.CreateToken(tokenDescriptor);
            return encryptedToken as EncryptedSecurityToken;
        }

        public static ClaimsIdentity SamlClaimsIdentity
        {
            get => new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.NameIdentifier, "Bob", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.StreetAddress, "123AnyWhereStreet/r/nSomeTown/r/nUSA", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, Issuer, OriginalIssuer),
            });
        }

        private static string Issuer => "https://issuer.com";

        private static string OriginalIssuer = "https://orignialIssuer.com";


        /// <summary>
        /// Creates a SAML Token with the input parameters
        /// </summary>
        /// <param name="stsName">Name of the STS issuing the SAML Token</param>
        /// <param name="proofToken">Associated Proof Token will end up in SubjectConfirmation. Can be null, if so, Sender-Vouches will be in SubjectConfirmation </param>
        /// <param name="signingCredentials">Will be used to sign token</param>
        /// <param name="proofKeyEncryptionToken">Token to encrypt the proof key with</param>
        /// <param name="samlConditions">The Saml Conditions to be used in the construction of the SAML Token</param>
        /// <param name="samlAttributes">The Saml Attributes to be used in the construction of the SAML Token</param>
        /// <returns>A SAML Token</returns>
        public static SamlSecurityToken CreateSamlToken(string stsName,
                                                        BinarySecretSecurityToken proofToken,
                                                        SigningCredentials signingCredentials,
                                                        SecurityToken proofKeyEncryptionToken,
                                                        SamlConditions samlConditions,
                                                        IEnumerable<SamlAttribute> samlAttributes)
        {
            // is holder of key or bearer
            string confirmationType;

            // represents the user if a proofToken is available
            SecurityKeyIdentifier ski = null;

            if (proofToken != null)
            {
                confirmationType = SamlConstants.HolderOfKey;
                // the key clause that is for the user


                if (proofKeyEncryptionToken != null)
                {
                    byte[] wrappedKey = proofKeyEncryptionToken.SecurityKeys[0].EncryptKey(SecurityAlgorithms.RsaOaepKeyWrap, proofToken.GetKeyBytes());
                    SecurityKeyIdentifierClause encryptingTokenClause = proofKeyEncryptionToken.CreateKeyIdentifierClause<X509ThumbprintKeyIdentifierClause>();
                    EncryptedKeyIdentifierClause encryptedKeyClause = new EncryptedKeyIdentifierClause(wrappedKey, SecurityAlgorithms.RsaOaepKeyWrap, new SecurityKeyIdentifier(encryptingTokenClause));
                    ski = new SecurityKeyIdentifier(encryptedKeyClause);
                }
                else
                {
                    ski = new SecurityKeyIdentifier(new BinarySecretKeyIdentifierClause(proofToken.GetKeyBytes()));
                }

            }
            else
            {
                confirmationType = SamlConstants.SenderVouches;
            }

            List<string> confirmationMethods = new List<string>(1);
            confirmationMethods.Add(confirmationType);

            SamlSubject samlSubject = new SamlSubject(null,
                                                      null,
                                                      null,
                                                      confirmationMethods,
                                                      null,
                                                      ski);

            // to use this token to sign we need to attach the proof token
            if (proofToken != null && proofToken.SecurityKeys != null && proofToken.SecurityKeys[0] != null)
            {
                samlSubject.Crypto = proofToken.SecurityKeys[0];
            }

            List<SamlStatement> samlSubjectStatements = new List<SamlStatement>();
            SamlAttributeStatement samlAttributeStatement = new SamlAttributeStatement(samlSubject, samlAttributes);
            samlSubjectStatements.Add(samlAttributeStatement);

            String id = "_" + Guid.NewGuid().ToString();
            SamlAssertion samlAssertion = new SamlAssertion(id,
                                                            stsName,
                                                            DateTime.UtcNow,
                                                            samlConditions,
                                                            new SamlAdvice(),
                                                            samlSubjectStatements
                                                            );
            samlAssertion.SigningCredentials = signingCredentials;

            return new SamlSecurityToken(samlAssertion);
        }


        public static string SignAndStreamSamlToken(SamlSecurityToken token)
        {
            MemoryStream ms = new MemoryStream();
            SecurityTokenSerializer serializer = WSSecurityTokenSerializer.DefaultInstance;

            XmlWriter writer = XmlWriter.Create(ms);
            serializer.WriteToken(writer, token);
            writer.Close();

            string tokenAsString = Encoding.UTF8.GetString(ms.ToArray());

            return tokenAsString;
        }
    }
}
