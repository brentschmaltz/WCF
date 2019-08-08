using System.Configuration;

namespace SelfHostSTS
{
    /// <summary>
    /// Defines the <claim> element in the config.
    /// </summary>
    public class ClaimConfigurationElement : ConfigurationElement
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public ClaimConfigurationElement()
        {
        }

        /// <summary>
        /// Creats an object of <see cref="ClaimElement"/>.
        /// </summary>
        /// <param name="newType"></param>
        /// <param name="newDisplayName"></param>
        /// <param name="newValue"></param>
        public ClaimConfigurationElement(string newType, string newDisplayName, string newValue)
        {
            Type = newType;
            DisplayName = newDisplayName;
            Value = newValue;
        }

        /// <summary>
        /// Creats an object of <see cref="ClaimElement"/>.
        /// </summary>
        public ClaimConfigurationElement(string elementName)
        {
            Type = elementName;
        }

        /// <summary>
        /// Gets or set the type attribute.
        /// </summary>
        [ConfigurationProperty(Constants.Type, IsRequired = true)]
        public string Type
        {
            get => (string)this[Constants.Type];
            set => this[Constants.Type] = value;
        }

        /// <summary>
        /// Gets or set the displayName attribute.
        /// </summary>
        [ConfigurationProperty(Attributes.DisplayName, IsRequired = true)]
        public string DisplayName
        {
            get => (string)this[Attributes.DisplayName];
            set => this[Attributes.DisplayName] = value;
        }

        /// <summary>
        /// Gets or set the value attribute.
        /// </summary>
        [ConfigurationProperty(Attributes.Value, IsRequired = false)]
        public string Value
        {
            get => (string)this[Attributes.Value];
            set => this[Attributes.Value] = value;
        }

        protected override void DeserializeElement(System.Xml.XmlReader reader, bool serializeCollectionKey)
        {
            base.DeserializeElement(reader, serializeCollectionKey);
        }

        protected override bool SerializeElement(System.Xml.XmlWriter writer, bool serializeCollectionKey)
        {
            return base.SerializeElement(writer, serializeCollectionKey);
        }

        protected override bool IsModified()
        {
            return base.IsModified();
        }
    }
}