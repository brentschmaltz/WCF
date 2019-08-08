using System;
using System.Configuration;
using System.IdentityModel.Metadata;

namespace SelfHostSTS
{
    /// <summary>
    /// Defines a configuration collection for adding values to <see cref="SecurityTokenServiceDescriptor"/>.
    /// Each entry in app.config should be a <see cref="ClaimConfigurationElement"/>.
    /// </summary>
    public class ClaimConfigurationElementCollection : ConfigurationElementCollection
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public ClaimConfigurationElementCollection()
        {
        }

        /// <summary>
        /// Gets the collection type.
        /// </summary>
        public override ConfigurationElementCollectionType CollectionType
        {
            get => ConfigurationElementCollectionType.AddRemoveClearMap;
        }


        public ClaimConfigurationElement this[int index]
        {
            get 
            {
                return (ClaimConfigurationElement)BaseGet(index);
            }
            set
            {
                if (BaseGet(index) != null)
                {
                    BaseRemoveAt(index);
                }

                BaseAdd(index, value);
            }
        }

        /// <summary>
        /// Creats a new element.
        /// </summary>
        /// <returns></returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new ClaimConfigurationElement();
        }

        /// <summary>
        /// Creates a new element with name <paramref name="elementName"/>
        /// </summary>
        /// <param name="elementName"></param>
        /// <returns></returns>
        protected override ConfigurationElement CreateNewElement(string elementName)
        {
            return new ClaimConfigurationElement(elementName);
        }

        /// <summary>
        ///  Gets the element key for a <see cref="ClaimConfigurationElement"/>.
        /// </summary>
        /// <param name="element">the <see cref="ClaimConfigurationElement"/> to return the key for.</param>
        /// <returns>a new <see cref="Guid"/> as a string.</returns>
        protected override object GetElementKey(ConfigurationElement element)
        {
            return Guid.NewGuid().ToString();
        }
    }
}