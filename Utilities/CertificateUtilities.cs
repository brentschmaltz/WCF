// ----------------------------------------------------------------------------
// Copyright (C) 2008 Microsoft Corporation, All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace SampleUtilities
{
    [Serializable]
    public struct CertFindQuad
    {
        public CertFindQuad(string queryValue, X509FindType findType, StoreLocation storeLocation, StoreName storeName)
        {
            this.QueryValue = queryValue;
            this.FindType = findType;
            this.StoreLocation = storeLocation;
            this.StoreName = storeName;
        }

        public string QueryValue;
        public X509FindType FindType;
        public StoreLocation StoreLocation;
        public StoreName StoreName;

    }

    public class CertificateUtilities
    {
        public static X509SecurityToken GetX509Token(string subject, StoreName storeName, StoreLocation storeLocation)
        {
            X509Store store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, subject, false);
                X509Certificate2 certificate = (X509Certificate2)certs[0];
                X509SecurityToken t = new X509SecurityToken(certificate);
                return t;
            }
            catch
            {
                Console.WriteLine("Cannot find certificate CN=client.com in the CurrentUser/My store");
                throw;
            }
            finally
            {
                store.Close();
            }
        }

        public static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, X509FindType findType, object value)
        {
            X509Store store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 cert = null;

            try
            {
                X509Certificate2Collection collection = store.Certificates.Find(findType, value, false);
                if (collection.Count == 0)
                {
                    throw new InvalidProgramException(string.Format("Cert not found: StoreName: '{0}', StoreLocation: '{1}', X509FindType: '{2}', findValue: '{3}'", name, location, findType, value));
                }

                return store.Certificates.Find(findType, value, false)[0];
            }
            catch (InvalidProgramException)
            {
                // ignore as 
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unable to extract Certificate: {0}", ex.ToString());
                throw;
            }
            finally
            {
                store.Close();
            }

            return cert;
        }

        public static X509Certificate2 FindCertificate(string queryValue, X509FindType findType, StoreName storeName, StoreLocation storeLocation)
        {
            return FindCertificate(new CertFindQuad(queryValue, findType, storeLocation, storeName));
        }

        public static X509Certificate2 FindCertificate(CertFindQuad findQuad)
        {

            X509Store store = new X509Store(findQuad.StoreName, findQuad.StoreLocation);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = store.Certificates.Find(findQuad.FindType, findQuad.QueryValue, false);
            //failed to find a cert
            if (0 == certificates.Count)
            {
                return null;
            }
            //found too many certs
            if (1 < certificates.Count)
            {
                throw new InvalidOperationException(String.Format("Found {0} certificates in {1}/{2} store for {3}",
                                                                  certificates.Count,
                                                                  findQuad.StoreLocation,
                                                                  findQuad.StoreName,
                                                                  findQuad.QueryValue));
            }
            //found exactly one certificate
            return certificates[0];
        }

        public static X509Certificate2 FindCertificateByName(string queryValue, StoreName storeName, StoreLocation storeLocation, X509NameType alternativeName)
        {
            return FindCertificateByName(queryValue, storeName, storeLocation, X509FindType.FindBySubjectDistinguishedName, alternativeName);
        }

        public static X509Certificate2 FindCertificateByName(string queryValue, StoreName storeName, StoreLocation storeLocation, X509FindType findType, X509NameType alternativeName)
        {
            //open target store
            X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            //try looking for certificates by subject name
            X509Certificate2Collection certificates = store.Certificates.Find(findType, queryValue, false);
            //if subject name lookup failed, fall back to subject alternative name
            if (0 == certificates.Count)
            {
                StringComparison comparisonMethod = StringComparison.InvariantCulture;
                if (X509NameType.DnsName == alternativeName ||
                    X509NameType.EmailName == alternativeName)
                {
                    // UPNs are case sensitive, though it is seldom enforced
                    comparisonMethod = StringComparison.InvariantCultureIgnoreCase;
                }
                foreach (X509Certificate2 certificate in store.Certificates)
                {
                    string certificateAlternativeName = certificate.GetNameInfo(alternativeName, false);
                    if (String.Equals(queryValue, certificateAlternativeName, comparisonMethod))
                    {
                        certificates.Add(certificate);
                    }
                }
            }
            //failed to find a cert
            if (0 == certificates.Count)
            {
                return null;
            }
            //found too many certs
            if (1 < certificates.Count)
            {
                throw new InvalidOperationException(String.Format("Found {0} certificates in {1}/{2} store for {3}",
                                                                  certificates.Count,
                                                                  storeLocation,
                                                                  storeName,
                                                                  queryValue));
            }
            //found exactly one certificate
            return certificates[0];
        }
        public static X509Certificate2 FindMachineCertificate()
        {
            string fullyQualifiedDnsName = MachineCertificateSubjectName();
            return FindCertificateByName(fullyQualifiedDnsName, StoreName.My, StoreLocation.LocalMachine, X509FindType.FindBySubjectName, X509NameType.DnsName);
        }

        public static string MachineCertificateSubjectName()
        {
            string fullyQualifiedDnsName = System.Net.Dns.GetHostEntry("").HostName;
            return fullyQualifiedDnsName;
        }

        public static X509Certificate2 GetCertFromMyLocalmachine( string subjectDistinguishedName )
        {
            return LookupCertificate( StoreName.My, StoreLocation.LocalMachine, subjectDistinguishedName );
        }

        public static X509Certificate2 LookupCertificate(StoreName storeName, StoreLocation storeLocation, string subjectDistinguishedName)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName,
                                                                           subjectDistinguishedName, false);
                if (certs.Count != 1)
                {
                    throw new Exception("FedUtil: Certificate not found or more than one certificate found");
                }
                return (X509Certificate2)certs[0];
            }
            finally
            {
                if (store != null) store.Close();
            }
        }

        public static X509Certificate2 LookupCertificate(StoreName storeName, StoreLocation storeLocation, X509FindType findtype, string findby)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(findtype, findby, false);
                if (certs.Count != 1)
                {
                    throw new Exception("FedUtil: Certificate not found or more than one certificate found");
                }
                return (X509Certificate2)certs[0];
            }
            finally
            {
                if (store != null) store.Close();
            }
        }

        public static X509SecurityToken GetX509TokenFromCert(StoreName storeName, StoreLocation storeLocation, string subjectDistinguishedName)
        {
            X509Certificate2 certificate = LookupCertificate(storeName, storeLocation, subjectDistinguishedName);
            X509SecurityToken t = new X509SecurityToken(certificate);
            return t;
        }

        public static X509SecurityToken GetX509TokenFromCert(StoreName storeName, StoreLocation storeLocation, X509FindType findtype, string find)
        {
            X509Certificate2 certificate = LookupCertificate(storeName, storeLocation, findtype, find);
            X509SecurityToken t = new X509SecurityToken(certificate);
            return t;
        }

        public static byte[] GetCertificateThumbprint(StoreName storeName, StoreLocation storeLocation, string subjectDistinguishedName)
        {
            X509Certificate2 certificate = LookupCertificate(storeName, storeLocation, subjectDistinguishedName);
            return certificate.GetCertHash();
        }
    }
}
