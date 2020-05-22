using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace CodeSnipits
{
    public class EncryptedSaml2Token
    {
        public static void Run(string[] args)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA"),
                new Claim(ClaimTypes.NameIdentifier, "Bob"),
                new Claim(ClaimTypes.Email, "Bob@contoso.com"),
                new Claim(ClaimTypes.GivenName, "Bob"),
                new Claim(ClaimTypes.HomePhone, "555.1212"),
                new Claim(ClaimTypes.Role, "Developer"),
                new Claim(ClaimTypes.Role, "Sales"),
                new Claim(ClaimTypes.StreetAddress, "123AnyWhereStreet\r\nSomeTown/r/nUSA"),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien"),
            };

            var keyClause = new X509ThumbprintKeyIdentifierClause(KeyMaterial.X509Certificate_2048_Public);
            var keyIdentifierPublic = new SecurityKeyIdentifier(keyClause);
            var notBefore = DateTime.UtcNow;
            var expires = notBefore + TimeSpan.FromDays(1);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                AppliesToAddress = "https://local.com",
                Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(notBefore, expires),
                //EncryptingCredentials = new EncryptedKeyEncryptingCredentials(KeyMaterial.X509Certificate_2048_Public),
                EncryptingCredentials = new EncryptedKeyEncryptingCredentials(new EncryptingCredentials(new X509AsymmetricSecurityKey(KeyMaterial.X509Certificate_2048_Public), keyIdentifierPublic, SecurityAlgorithms.RsaOaepKeyWrap), 256, SecurityAlgorithms.Aes256Encryption),
                //Proof = new ProofDescriptor
                SigningCredentials = new X509SigningCredentials(KeyMaterial.X509Certificate_2048),
                Subject = new ClaimsIdentity(claims),
                TokenIssuerName = "https://encryptedSaml2Token.com",
            };

            var saml2TokenHandler = new Saml2SecurityTokenHandler();
            var saml2Token = saml2TokenHandler.CreateToken(tokenDescriptor);

            var ms = new MemoryStream();
            var xmlWriter = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8);
            saml2TokenHandler.WriteToken(xmlWriter, saml2Token);
            xmlWriter.Flush();

            var saml2 = Encoding.UTF8.GetString(ms.ToArray());
            var xmlReader = XmlDictionaryReader.CreateTextReader(ms.ToArray(), XmlDictionaryReaderQuotas.Max);
            var issuerTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver((new List<SecurityToken> { new X509SecurityToken(KeyMaterial.X509Certificate_2048_Public) }).AsReadOnly(), true);
            var serviceTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver((new List<SecurityToken> { new X509SecurityToken(KeyMaterial.X509Certificate_2048) }).AsReadOnly(), true);
            var configuration = new SecurityTokenHandlerConfiguration
            {
                IssuerTokenResolver = issuerTokenResolver,
                ServiceTokenResolver = serviceTokenResolver
            };

            saml2TokenHandler.Configuration = configuration;

            var decryptedToken = saml2TokenHandler.ReadToken(xmlReader);
        }
    }
}
