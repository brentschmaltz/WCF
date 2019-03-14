
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;

namespace ChannelCredentials
{
    public class SamlTokenBuilder
    {
        public static Saml2SecurityToken CreateSaml2Token(string issuer,
                                                        SigningCredentials signingCredentials,
                                                        IEnumerable<Claim> claims)
        {
            var subject = new ClaimsIdentity(claims);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = signingCredentials,
                Subject = subject,
                TokenIssuerName = issuer
            };
            var tokenHandler = new Saml2SecurityTokenHandler();
            return tokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;
        }

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
                                                        IEnumerable<SamlAttribute> samlAttributes )
        {
            // is holder of key or bearer
            string confirmationType;

            // represents the user if a proofToken is available
            SecurityKeyIdentifier ski = null;

            if ( proofToken != null )
            {
                confirmationType = SamlConstants.HolderOfKey;
                // the key clause that is for the user


                if ( proofKeyEncryptionToken != null )
                {
                    byte[] wrappedKey = proofKeyEncryptionToken.SecurityKeys[0].EncryptKey( SecurityAlgorithms.RsaOaepKeyWrap, proofToken.GetKeyBytes() );
                    SecurityKeyIdentifierClause encryptingTokenClause = proofKeyEncryptionToken.CreateKeyIdentifierClause<X509ThumbprintKeyIdentifierClause>();
                    EncryptedKeyIdentifierClause encryptedKeyClause = new EncryptedKeyIdentifierClause( wrappedKey, SecurityAlgorithms.RsaOaepKeyWrap, new SecurityKeyIdentifier( encryptingTokenClause ) );
                    ski = new SecurityKeyIdentifier( encryptedKeyClause );
                }
                else
                {
                    ski = new SecurityKeyIdentifier( new BinarySecretKeyIdentifierClause( proofToken.GetKeyBytes() ) );
                }

            }
            else
            {
                confirmationType = SamlConstants.SenderVouches;
            }

            List<string> confirmationMethods = new List<string>( 1 );
            confirmationMethods.Add( confirmationType );

            SamlSubject samlSubject = new SamlSubject( null,
                                                      null,
                                                      null,
                                                      confirmationMethods,
                                                      null,
                                                      ski );

            // to use this token to sign we need to attach the proof token
            if ( proofToken != null && proofToken.SecurityKeys != null && proofToken.SecurityKeys[0] != null )
            {
                samlSubject.Crypto = proofToken.SecurityKeys[0];
            }

            List<SamlStatement> samlSubjectStatements = new List<SamlStatement>();
            SamlAttributeStatement samlAttributeStatement = new SamlAttributeStatement( samlSubject, samlAttributes );
            samlSubjectStatements.Add( samlAttributeStatement );

            String id = "_" + Guid.NewGuid().ToString();
            SamlAssertion samlAssertion = new SamlAssertion( id,
                                                            stsName,
                                                            DateTime.UtcNow,
                                                            samlConditions,
                                                            new SamlAdvice(),
                                                            samlSubjectStatements
                                                            );
            samlAssertion.SigningCredentials = signingCredentials;

            return new SamlSecurityToken( samlAssertion );
        }


        public static string SignAndStreamSamlToken( SamlSecurityToken token )
        {
            MemoryStream ms = new MemoryStream();
            SecurityTokenSerializer serializer = WSSecurityTokenSerializer.DefaultInstance;

            XmlWriter writer = XmlWriter.Create( ms );
            serializer.WriteToken( writer, token );
            writer.Close();

            string tokenAsString = Encoding.UTF8.GetString( ms.ToArray() );

            return tokenAsString;
        }
    }
}
