// ----------------------------------------------------------------------------
// CustomUserNamePasswordValidator
//  - checks that u/p against what was passed in constructor
// ----------------------------------------------------------------------------

using System;
using System.IdentityModel.Selectors;
using System.ServiceModel;

namespace WcfUtilities
{
    public class CustomUserNamePasswordValidator : UserNamePasswordValidator
    {
        private string _password;
        private string _userName;

        public CustomUserNamePasswordValidator(string userName, string password)
        {
            _userName = userName;
            _password = password;
        }

        public override void Validate(string userName, string password)
        {
            if (string.IsNullOrWhiteSpace(userName))
                throw new ArgumentNullException(nameof(userName));

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException(nameof(password));

            if (string.Equals(userName, _userName, StringComparison.Ordinal) && string.Equals(password, _password, StringComparison.Ordinal))
                return;

            throw new FaultException(new FaultReason("UserNamePasswordValidator.Validate Failed"), new FaultCode("UP Credential failure"));
        }
    }
}
