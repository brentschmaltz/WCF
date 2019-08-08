using System.IdentityModel.Tokens;
namespace WCFSecurityUtilities
{
    public class CustomKeyIdentifierClause : BinaryKeyIdentifierClause
    {
        static string clauseType = TokenTypes.Saml11;
        InMemorySymmetricSecurityKey symmetricKey;

        public CustomKeyIdentifierClause(byte[] identificationData, bool cloneBuffer)
            : base(clauseType, identificationData, cloneBuffer)
        {
        }

        public override bool CanCreateKey
        {
            get { return true; }
        }

        public override SecurityKey CreateKey()
        {
            if (this.symmetricKey == null)
                this.symmetricKey = new InMemorySymmetricSecurityKey(GetBuffer(), false);

            return this.symmetricKey;
        }

        public override bool Matches(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            CustomKeyIdentifierClause that = keyIdentifierClause as CustomKeyIdentifierClause;

            return ReferenceEquals(this, that) || (that != null && that.Matches(this.GetRawBuffer()));
        }

    }
}
