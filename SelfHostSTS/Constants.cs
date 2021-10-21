namespace SelfHostSTS
{
    /// <summary>
    /// Defines the constants used by this project.
    /// </summary>
    internal static class Attributes
    {
        /// <summary>
        /// These are the name of configuration values needed to run the STS.
        /// </summary>
        internal const string BaseAddress = "baseAddress";
        internal const string CertificateLocation = "certificateLocation";
        internal const string DisplayName = "displayName";
        internal const string HttpPort = "httpPort";
        internal const string HttpsPort = "httpsPort";
        internal const string IssuerName = "issuerName";
        internal const string MetadataCertificate = "metadataCertificate";
        internal const string MetadataCertificatePassword = "metadataCertificatePassword";
        internal const string RelyingPartyCertificate = "relyingPartyCertificate";
        internal const string SigningCertificate = "signingCertificate";
        internal const string SigningCertificatePassword = "sigingCertificatePassword";
        internal const string SslCertificate = "sslCertificate";
        internal const string SslCertificatePassword = "sslCertificatePassword";
        internal const string Type = "type";
        internal const string TokenFormat = "tokenFormat";
        internal const string Value = "value";
    }

    /// <summary>
    /// Defines the constants used by this project.
    /// </summary>
    internal static class Constants
    {
        /// <summary>
        /// This is the registry key where this package gets installed. The last part of the packge is replaced by the GUID value of this package.
        /// </summary>
        internal const string CodebaseRegistryKey = @"HKEY_CURRENT_USER\Software\Microsoft\VisualStudio\11.0_Config\Packages\{{{0}}}";
        internal const string Codebase = "CodeBase";
        internal const string Claims = "claims";
        internal const string ClaimType = "ClaimType";
        internal const string ClaimValue = "ClaimValue";
        internal const string ContentType = "text/html";
        internal const string DashStart = "-Start";
        internal const string FederationMetadataAddress = "FederationMetadata/2007-06/FederationMetadata.xml";
        internal const string FederationMetadataEndpoint = WSFedSTS + FederationMetadataAddress;
        internal const string GuidIdentityAndAccessVSPackagePkgString = "97e6cb8f-c650-43ea-a6f3-2b4a51ecc8d5";
        internal const string JWT = "JWT";
        internal const string SelfHostSTSCertificate = "SelfHostSTS.pfx";
        internal const string SelfHostStsExeConfig = "SelfHostSTS.exe.config";
        internal const string SelfHostSecurityTokenServiceConfiguration = "selfHostSecurityTokenServiceConfiguration";
        internal const string Saml2TokenType = "urn:oasis:names:tc:SAML:2.0:assertion";
        internal const string SDKFwdLink = "http://go.microsoft.com/fwlink/?LinkID=191420";
        internal const string SignInResponseMessageFormat = "?wa=wsignin1.0&wtrealm={0}&wctx={1}&wct={2}&wreply={3}&wreq={4}";
        internal const string Type = "type";
        internal const string UriTemplate = "/Issue/?wa=wsignin1.0&wtrealm={realm}&wctx={wctx}&wct={wct}&wreply={wreply}&wreq={wreq}";
        internal const string WSFedSTS = "/wsFederationSTS/";
        internal const string WSFedSTSIssue = WSFedSTS + "Issue";
        internal const string WSTrust13 = "/wsTrust13/";
        internal const string WSFederationMetadataNamespace = "http://docs.oasis-open.org/wsfed/federation/200706";
        internal const string WSTrustFeb2005Namespace = "http://schemas.xmlsoap.org/ws/2005/02/trust";
        internal const string WSTrust13Namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";        
    }
}
