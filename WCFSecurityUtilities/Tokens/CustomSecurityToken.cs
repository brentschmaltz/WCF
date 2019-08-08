using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security.Tokens;

namespace WCFSecurityUtilities
{

    public class CustomSecurityToken : SecurityToken
    {
        string id;
        DateTime effectiveTime;
        byte[] key;
        ReadOnlyCollection<SecurityKey> securityKeys;

        public CustomSecurityToken(BinarySecretSecurityToken proofToken)
        {
            if (proofToken == null)
                throw new ArgumentNullException("proofToken");

            if (proofToken.SecurityKeys == null)
                throw new ArgumentNullException("proofToken.SecurityKeys");

            if (proofToken.SecurityKeys.Count < 1)
                throw new ArgumentNullException("proofToken.SecurityKeys count < 1");

            this.id = Guid.NewGuid().ToString();
            this.effectiveTime = DateTime.UtcNow;
            this.securityKeys = proofToken.SecurityKeys;
            this.key = proofToken.GetKeyBytes();
        }

        public CustomSecurityToken(string id, byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            if (id == null)
                this.id = Guid.NewGuid().ToString();
            else
                this.id = id;

            this.effectiveTime = DateTime.UtcNow;
            this.key = new byte[key.Length];
            Buffer.BlockCopy(key, 0, this.key, 0, key.Length);
            this.securityKeys = CreateSymmetricSecurityKeys(this.key);
        }

        public override bool CanCreateKeyIdentifierClause<T>()
        {
            if (typeof(T) == typeof(CustomKeyIdentifierClause))
                return true;

            if (typeof(T) == typeof(LocalIdKeyIdentifierClause))
                return true;

            return false;
        }

        public override T CreateKeyIdentifierClause<T>()
        {
            if (typeof(T) == typeof(CustomKeyIdentifierClause))
                return new CustomKeyIdentifierClause(this.key, true) as T;

            if (typeof(T) == typeof(LocalIdKeyIdentifierClause))
                return new LocalIdKeyIdentifierClause(this.id, this.GetType()) as T;

            if (typeof(T) == typeof(SamlAssertionKeyIdentifierClause))
                return new LocalIdKeyIdentifierClause(this.id, this.GetType()) as T;

            throw new InvalidOperationException("Unable to create Token Reference");
        }

        public byte[] Key()
        {
            return (new InMemorySymmetricSecurityKey(key)).GetSymmetricKey();
        }

        public override bool MatchesKeyIdentifierClause(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            CustomKeyIdentifierClause customKeyIdentifierClause = keyIdentifierClause as CustomKeyIdentifierClause;            
            if (customKeyIdentifierClause != null)
                return customKeyIdentifierClause.Matches(this.key);

            LocalIdKeyIdentifierClause localIdKeyIdentifierClause = keyIdentifierClause as LocalIdKeyIdentifierClause;
            if (localIdKeyIdentifierClause != null)
            {
#if DEBUG
                bool match;
                match = localIdKeyIdentifierClause.LocalId == this.id;
                localIdKeyIdentifierClause.Matches(this.id, this.GetType());
#endif
                return (localIdKeyIdentifierClause.LocalId == this.id);
            }
            return false;
        }

        public override SecurityKey ResolveKeyIdentifierClause(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            if (this.SecurityKeys.Count != 0 && MatchesKeyIdentifierClause(keyIdentifierClause))
                return this.SecurityKeys[0];

            return null;
        }

        public override string Id
        {
            get { return this.id; }
        }

        public override DateTime ValidFrom
        {
            get { return this.effectiveTime; }
        }

        public override DateTime ValidTo
        {
            // Never expire
            get { return DateTime.MaxValue; }
        }

        public override ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get { return this.securityKeys; }
        }

        protected ReadOnlyCollection<SecurityKey> CreateSymmetricSecurityKeys(byte[] key)
        {
            List<SecurityKey> temp = new List<SecurityKey>(1);
            temp.Add(new InMemorySymmetricSecurityKey(key));
            return temp.AsReadOnly();
        }

    }
}
