using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace CertUtils
{
    public class CertificateUtilities
    {
        public static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, X509FindType findType, object value)
        {
            var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 cert = null;

            try
            {
                var collection = store.Certificates.Find(findType, value, false);
                if (collection.Count == 0)
                    throw new InvalidProgramException(string.Format("Cert not found: StoreName: '{0}', StoreLocation: '{1}', X509FindType: '{2}', findValue: '{3}'", name, location, findType, value));

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

        public static X509SecurityToken GetX509Token(StoreName storeName, StoreLocation storeLocation, X509FindType findType, object value)
        {         
             return new X509SecurityToken(GetCertificate(storeName, storeLocation, findType, value));
        }

        public static string MachineCertificateSubjectName()
        {
            string fullyQualifiedDnsName = System.Net.Dns.GetHostEntry("").HostName;
            return fullyQualifiedDnsName;
        }
    }
}
