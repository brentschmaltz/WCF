using System;
using System.Configuration;
using System.IO;

namespace SelfHostSTS
{
    /// <summary>
    /// Provides a class to parse the selfHostSecurityTokenServiceConfiguration configuration section.
    /// </summary>
    public class SelfHostSecurityTokenServiceConfigurationSection : ConfigurationSection
    {
        static SelfHostSecurityTokenServiceConfigurationSection _stsConfiguration = null;
        string _sslPfxCertificateFileLocation;
        string _metadataPfxCertificateFileLocation;

        /// <summary>
        /// Gets the certificate file location.
        /// </summary>
        internal string SslPfxLocation
        {
            get => _sslPfxCertificateFileLocation;
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw new ArgumentNullException(nameof(value));

                _sslPfxCertificateFileLocation = value;
            }
        }

        /// <summary>
        /// Gets the certificate file location.
        /// </summary>
        internal string MetadataPfxCertificateLocation
        {
            get => _metadataPfxCertificateFileLocation;
        }

        /// <summary>
        /// Gets the current <see cref="StsConfiguration"/> object.
        /// </summary>
        /// <param name="location"></param>
        /// <returns></returns>
        public static SelfHostSecurityTokenServiceConfigurationSection StsConfiguration
        {
            get
            {
                if (_stsConfiguration != null)
                    return _stsConfiguration;

                if (ConfigurationManager.GetSection(Constants.SelfHostSecurityTokenServiceConfiguration) is SelfHostSecurityTokenServiceConfigurationSection section)
                {
                    _stsConfiguration = section;
                    if (_stsConfiguration.SSLCertificate != null)
                        _stsConfiguration._sslPfxCertificateFileLocation = Path.Combine(_stsConfiguration.CertificateLocation, _stsConfiguration.SSLCertificate);

                    if (!File.Exists(_stsConfiguration._sslPfxCertificateFileLocation))
                        throw new InvalidOperationException(string.Format("SSL Certificate file not found: '{0}'.", _stsConfiguration._sslPfxCertificateFileLocation));

                    if (_stsConfiguration.MetadataCertificate != null)
                        _stsConfiguration._metadataPfxCertificateFileLocation = System.IO.Path.Combine(_stsConfiguration.CertificateLocation, _stsConfiguration.MetadataCertificate);

                    if (!File.Exists(_stsConfiguration._metadataPfxCertificateFileLocation))
                        throw new InvalidOperationException(string.Format("Metadata signing certificate file not found: '{0}'.", _stsConfiguration._metadataPfxCertificateFileLocation));
                }

                return _stsConfiguration;
            }
        }

        /// <summary>
        /// Gets or set the port attribute. Default is 8000.
        /// </summary>
        [ConfigurationProperty(Attributes.BaseAddress, DefaultValue = "https://localhost", IsRequired = true, IsKey = false)]
        public string BaseAddress
        {
            get => (string)this[Attributes.BaseAddress];
            set => this[Attributes.BaseAddress] = value;
        }

        /// <summary>
        /// Gets or set the port attribute. Default is 8000.
        /// </summary>
        [ConfigurationProperty(Attributes.CertificateLocation, DefaultValue = @"C:\Certs", IsRequired = true, IsKey = false)]
        public string CertificateLocation
        {
            get => (string)this[Attributes.CertificateLocation];
            set => this[Attributes.CertificateLocation] = value;
        }

        /// <summary>
        /// Gets or set the port attribute. Default is 8000.
        /// </summary>
        [ConfigurationProperty(Attributes.HttpsPort, DefaultValue = "5443", IsRequired = true, IsKey = false)]
        public string HttpsPort
        {
            get => (string)this[Attributes.HttpsPort];
            set => this[Attributes.HttpsPort] = value;
        }

        /// <summary>
        /// Gets or set the http port attribute. Default is 8080.
        /// </summary>
        [ConfigurationProperty(Attributes.HttpPort, DefaultValue = "8080", IsRequired = true, IsKey = false)]
        public string HttpPort
        {
            get => (string)this[Attributes.HttpPort];
            set => this[Attributes.HttpPort] = value;
        }

        /// <summary>
        /// Gets or sets the signing certificate attribute.
        /// </summary>
        [ConfigurationProperty(Attributes.MetadataCertificate, IsRequired = true, IsKey = false)]
        public string MetadataCertificate
        {
            get => (string)this[Attributes.MetadataCertificate];
            set => this[Attributes.MetadataCertificate] = value;
        }

        /// <summary>
        /// Gets or sets the signing certificate password.
        /// </summary>
        [ConfigurationProperty(Attributes.MetadataCertificatePassword, IsRequired = true, IsKey = false)]
        public string MetadataCertificatePassword
        {
            get => (string)this[Attributes.MetadataCertificatePassword];
            set => this[Attributes.MetadataCertificatePassword] = value;
        }

        /// <summary>
        /// Gets or sets the signing certificate attribute.
        /// </summary>
        [ConfigurationProperty(Attributes.SSLCertificate, IsRequired = true, IsKey = false)]
        public string SSLCertificate
        {
            get =>(string)this[Attributes.SSLCertificate];
            set => this[Attributes.SSLCertificate] = value;
        }

        /// <summary>
        /// Gets or sets the signing certificate password.
        /// </summary>
        [ConfigurationProperty(Attributes.SSLCertificatePassword, IsRequired = true, IsKey = false)]
        public string SSLCertificatePassword
        {
            get => (string)this[Attributes.SSLCertificatePassword];
            set => this[Attributes.SSLCertificatePassword] = value;
        }

        /// <summary>
        /// Gets or sets the issuer name attribute.
        /// </summary>
        [ConfigurationProperty(Attributes.IssuerName, IsRequired = true, IsKey = false)]
        public string IssuerName
        {
            get => (string)this[Attributes.IssuerName];
            set => this[Attributes.IssuerName] = value;
        }

        /// <summary>
        /// Gets the claims collection element.
        /// </summary>
        [ConfigurationProperty(Constants.Claims, IsDefaultCollection = false)]
        public ClaimConfigurationElementCollection Claims => (ClaimConfigurationElementCollection)base[Constants.Claims];

        protected override void DeserializeSection(System.Xml.XmlReader reader)
        {
            base.DeserializeSection(reader);
        }

        protected override string SerializeSection(ConfigurationElement parentElement, string name, ConfigurationSaveMode saveMode)
        {
            return base.SerializeSection(parentElement, name, saveMode);
        }
    }
}