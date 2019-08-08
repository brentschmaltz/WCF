using System;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace WCFSecurityUtilities
{
    public class Constants
    {
        public const string RequestSecurityTokenAction = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
        public const string RequestSecurityTokenResponseAction = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue";
        
        public static StoreName CertStoreName = StoreName.My;
        public static StoreLocation CertStoreLocation = StoreLocation.LocalMachine;
        
        public static string authorizationDumpLocationDefault = "D:\\Logs\\ClaimDump.xml";
        public static string authorizationDumpLocation;

        public static string AuthorizationDumpLocation
        {
            get
            {
                if (Constants.authorizationDumpLocation == null)
                    Constants.authorizationDumpLocation = Constants.authorizationDumpLocationDefault;

                return Constants.authorizationDumpLocation; 
            }
        }

        public static void LoadAppSettings()
        {
            Constants.authorizationDumpLocation = Constants.authorizationDumpLocationDefault;
        }

        private static void CheckIfLoaded(string s)
        {
            if (String.IsNullOrEmpty(s))
            {
                throw new ConfigurationErrorsException("Required Configuration Element(s) missing at BookStoreService. Please check the service configuration file.");
            }
        }

        // Various constants for WS-Trust
        public class Trust
        {
            public const string NamespaceUri = "http://schemas.xmlsoap.org/ws/2005/02/trust";

            public class Actions
            {
                public const string Issue = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
                public const string IssueReply = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue";
            }

            public class Attributes
            {
                public const string Context = "Context";
            }

            public class Elements
            {
                public const string KeySize = "KeySize";
                public const string Entropy = "Entropy";
                public const string BinarySecret = "BinarySecret";
                public const string RequestSecurityToken = "RequestSecurityToken";
                public const string RequestSecurityTokenResponse = "RequestSecurityTokenResponse";
                public const string TokenType = "TokenType";
                public const string RequestedSecurityToken = "RequestedSecurityToken";
                public const string RequestedAttachedReference = "RequestedAttachedReference";
                public const string RequestedUnattachedReference = "RequestedUnattachedReference";
                public const string RequestedProofToken = "RequestedProofToken";
                public const string ComputedKey = "ComputedKey";
            }

            public class ComputedKeyAlgorithms
            {
                public const string PSHA1 = "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1";
            }
        }

        // Various constants for WS-Policy
        public class Policy
        {
            public const string NamespaceUri = "http://schemas.xmlsoap.org/ws/2004/09/policy";

            public class Elements
            {
                public const string AppliesTo = "AppliesTo";
            }
        }

        // Various constants for WS-Addressing
        public class Addressing
        {
            public const string NamespaceUri = "http://www.w3.org/2005/08/addressing";

            public class Elements
            {
                public const string EndpointReference = "EndpointReference";
            }
        }
    }
}

 
