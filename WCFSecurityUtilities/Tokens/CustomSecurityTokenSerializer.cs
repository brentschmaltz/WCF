using System;
using System.Collections.Generic;
using System.IdentityModel.Policy;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;
using System.Xml;

namespace WCFSecurityUtilities
{
    public class CustomSecurityTokenSerializer : WSSecurityTokenSerializer
    {

        public CustomSecurityTokenSerializer(SecurityVersion sv)
            : base(sv)
        {
        }

        protected override bool CanReadTokenCore(XmlReader reader)
        {
            if (reader.IsStartElement("CustomSecurityToken", "http://www.customtoken.org"))
                return true;

            else return base.CanReadToken(reader);
        }

        protected override SecurityToken ReadTokenCore(XmlReader reader, SecurityTokenResolver tokenResolver)
        {
            if (base.CanReadTokenCore(reader))
                return base.ReadTokenCore(reader, tokenResolver);
            
            // read as a generic XML token.
            XmlDictionaryReader dicReader = XmlDictionaryReader.CreateDictionaryReader(reader);
            string id = dicReader.GetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            byte[] secret = dicReader.ReadElementContentAsBase64();
            //XmlElement xe = new XmlElement();
            List<IAuthorizationPolicy> policies = new List<IAuthorizationPolicy>();
            policies.Add(new CustomSecurityAuthorizationPolicy());
            CustomSecurityToken customSecurityToken = new CustomSecurityToken(id, secret);

            XmlDocument dom = new XmlDocument();
            XmlElement tokenAsXmlElement = dom.CreateElement("prefix", "CustomSecurityToken", "http://www.customtoken.org");
            XmlAttribute xmla = tokenAsXmlElement.SetAttributeNode("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            xmla.Value = customSecurityToken.Id;
            GenericXmlSecurityToken genericToken = new GenericXmlSecurityToken(tokenAsXmlElement, customSecurityToken, DateTime.UtcNow, DateTime.MaxValue.ToUniversalTime(), customSecurityToken.CreateKeyIdentifierClause<LocalIdKeyIdentifierClause>(), customSecurityToken.CreateKeyIdentifierClause<LocalIdKeyIdentifierClause>(), policies.AsReadOnly());
            //return new CustomSecurityToken(id, secret);
            return genericToken;
         }

        protected override void WriteTokenCore(XmlWriter writer, SecurityToken token)
        {
            CustomSecurityToken customSecurityToken = token as CustomSecurityToken;
            if (customSecurityToken != null)
            {
                byte[] secret = customSecurityToken.Key();
                //writer.WriteStartElement(TokenTypes.CustomToken);
                writer.WriteStartElement("prefix", "CustomSecurityToken", "http://www.customtoken.org");
                writer.WriteAttributeString("u", "Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", token.Id);
                writer.WriteBase64(secret, 0, secret.Length);
                writer.WriteEndElement();
                return;
            }
            base.WriteTokenCore(writer, token);
        }

        protected override void WriteKeyIdentifierClauseCore(XmlWriter writer, SecurityKeyIdentifierClause keyIdentifierClause)
        {
            CustomKeyIdentifierClause customKeyIdentifierClause = keyIdentifierClause as CustomKeyIdentifierClause;
            if (customKeyIdentifierClause != null)
            {
                byte[] secret = customKeyIdentifierClause.GetBuffer();
                writer.WriteStartElement("prefix", "CustomKeyIdentifierClause", "http://www.customtoken.org");
                writer.WriteBase64(secret, 0, secret.Length);
                writer.WriteEndElement();
                return;
            }
            base.WriteKeyIdentifierClauseCore(writer, keyIdentifierClause);
        }

        protected override bool CanReadKeyIdentifierClauseCore(XmlReader reader)
        {
            if (reader.IsStartElement("CustomKeyIdentifierClause", "http://www.customtoken.org"))
                return true;

            return base.CanReadKeyIdentifierCore(reader);
        }

        protected override SecurityKeyIdentifierClause ReadKeyIdentifierClauseCore(XmlReader reader)
        {
            if (CanReadKeyIdentifierClauseCore(reader))
            {
                XmlDictionaryReader dicReader = XmlDictionaryReader.CreateDictionaryReader(reader);
                byte[] secret = dicReader.ReadElementContentAsBase64();
                return new CustomKeyIdentifierClause(secret, false);
            }

            return base.ReadKeyIdentifierClauseCore(reader);
        }
    }
}
