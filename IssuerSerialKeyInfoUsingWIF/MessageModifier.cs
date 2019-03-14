//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Xml;

namespace IssuerSerialKeyInfo
{
    public class MessageModifier
    {
        /// <summary>
        /// Transform message by:
        /// 1. Scan message for KeyInfo that has Security
        /// 1. Add BinarySecurityToken after Timestamp.
        /// 2. Add replace KeyInfo with SecurityTokenReference.
        /// </summary>
        /// <param name="message"></param>
        public virtual void OnReceive(ref Message message)
        {
            var messageStream = new MemoryStream();
            message.CreateBufferedCopy(Int32.MaxValue).WriteMessage(messageStream);
            var cert = GetCertFromMessage(messageStream);
            messageStream.Position = 0;

            var writerStream = new MemoryStream();
            var xmlReader = XmlDictionaryReader.CreateDictionaryReader(XmlDictionaryReader.Create(messageStream));
            var xmlWriter = XmlDictionaryWriter.CreateDictionaryWriter(XmlDictionaryWriter.Create(writerStream));
            var id = Guid.NewGuid().ToString();
            while (xmlReader.Read())
            {
                if (xmlReader.IsStartElement("Signature"))
                {
                    var x509Data = Convert.ToBase64String(cert.GetRawCertData());
                    xmlWriter.WriteStartElement("BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
                    xmlWriter.WriteAttributeString("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", id);
                    xmlWriter.WriteAttributeString("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
                    xmlWriter.WriteAttributeString("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
                    xmlWriter.WriteString(x509Data);
                    xmlWriter.WriteEndElement();
                    RecordNode(xmlReader, xmlWriter);
                }
                else if (xmlReader.IsStartElement("KeyInfo"))
                {
                    // <KeyInfo>
                    //  <o:SecurityTokenReference>
                    //      <o:Reference URI="#uuid-3e2d55a1-1aa2-413d-a166-3d034ac2cea1-2"></o:Reference>
                    //  </o:SecurityTokenReference>
                    // </KeyInfo>

                    xmlWriter.WriteStartElement("KeyInfo");
                    xmlWriter.WriteStartElement("SecurityTokenReference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
                    xmlWriter.WriteStartElement("Reference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
                    xmlWriter.WriteAttributeString("URI", "#" + id);
                    xmlWriter.WriteEndElement();
                    xmlWriter.WriteEndElement();
                    xmlWriter.WriteEndElement();
                    xmlReader.ReadOuterXml();
                    RecordNode(xmlReader, xmlWriter);
                }
                else
                    RecordNode(xmlReader, xmlWriter);
            }

            xmlWriter.Flush();
            writerStream.Position = 0;
            var modifiedMessage = Message.CreateMessage(XmlReader.Create(writerStream), 2147483647, message.Version);
            var modifiedBuffer = modifiedMessage.CreateBufferedCopy(Int32.MaxValue);
            message = modifiedBuffer.CreateMessage();
        }


        private X509Certificate2 GetCertFromMessage(MemoryStream messageStream)
        {
            string issuerName = null;
            string serialNumber = null;

            messageStream.Position = 0;
            var xmlReader = XmlDictionaryReader.CreateDictionaryReader(XmlDictionaryReader.Create(messageStream));
            while (xmlReader.Read())
            {
                if (xmlReader.IsStartElement("X509IssuerName"))
                    issuerName = xmlReader.ReadString();
                else if (xmlReader.IsStartElement("X509SerialNumber"))
                    serialNumber = xmlReader.ReadString();
            }

            return LoadCert(issuerName, serialNumber, StoreName.My, StoreLocation.LocalMachine);
        }

        private X509Certificate2 LoadCert(string issuerName, string serialNumber, StoreName storeName, StoreLocation storeLocation)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySerialNumber, serialNumber, false);
                if (certs.Count != 1)
                    throw new Exception("Certificate not found or more than one certificate found");

                return (X509Certificate2)certs[0];
            }
            finally
            {
                if (store != null) store.Close();
            }
        }

        /// <summary>
        /// Writes the current node into the writer
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="writer"></param>
        private static void RecordNode(XmlReader reader, XmlWriter writer)
        {
            switch (reader.NodeType)
            {
                case XmlNodeType.CDATA:
                    writer.WriteCData(reader.Value);
                    break;
                case XmlNodeType.Comment:
                    writer.WriteComment(reader.Value);
                    break;

                case XmlNodeType.DocumentType:
                    writer.WriteDocType(reader.Name, reader.GetAttribute("PUBLIC"), reader.GetAttribute("SYSTEM"), reader.Value);
                    break;

                case XmlNodeType.Element:
                    writer.WriteStartElement(reader.Prefix, reader.LocalName, reader.NamespaceURI);
                    writer.WriteAttributes(reader, true);
                    if (reader.IsEmptyElement)
                        writer.WriteEndElement();
                    break;

                case XmlNodeType.EndElement:
                    writer.WriteFullEndElement();
                    break;

                case XmlNodeType.Text:
                    writer.WriteString(reader.Value);
                    break;

                case XmlNodeType.Whitespace:
                case XmlNodeType.SignificantWhitespace:
                    writer.WriteWhitespace(reader.Value);
                    break;

                case XmlNodeType.EntityReference:
                    writer.WriteEntityRef(reader.Name);
                    break;

                case XmlNodeType.XmlDeclaration:
                case XmlNodeType.ProcessingInstruction:
                    writer.WriteProcessingInstruction(reader.Name, reader.Value);
                    break;

            }
        }

        public virtual void OnExportPolicy(MetadataExporter exporter, PolicyConversionContext context){}

        public virtual void OnImportPolicy(MetadataImporter importer, PolicyConversionContext context){}
    }
}
