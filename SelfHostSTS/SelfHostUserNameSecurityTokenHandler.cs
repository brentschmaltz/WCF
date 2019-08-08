using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace SelfHostSTS
{
    /// <summary>
    /// This token handler validation all UserNameSecurityToken and returns a <see cref="ReadOnlyCollection{ClaimsIdentity}"/> with a single claim, the username found in the token.
    /// </summary>
    public class SelfHostUserNameSecurityTokenHandler : UserNameSecurityTokenHandler
    {
        /// <summary>
        /// Returns true to indicate that the token handler can Validate
        /// UserNameSecurityToken.
        /// </summary>
        public override bool CanValidateToken => true;

        /// <summary>
        /// Validates a <see cref="UserNameSecurityToken"/>.
        /// </summary>
        /// <param name="token">The <see cref="UserNameSecurityToken"/> to validate.</param>
        /// <returns>A <see cref="ReadOnlyCollection{T}"/> of <see cref="ClaimsIdentity"/> representing the identities contained in the token.</returns>
        /// <exception cref="ArgumentNullException">The parameter 'token' is null.</exception>
        /// <exception cref="ArgumentException">The token is not assignable from<see cref="UserNameSecurityToken"/>.</exception>
        /// <exception cref="InvalidOperationException">Configuration <see cref="SecurityTokenHandlerConfiguration"/>is null.</exception>
        /// <exception cref="ArgumentException">If username is not if the form 'user\domain'.</exception>
        /// <exception cref="SecurityTokenValidationException">LogonUser using the given token failed.</exception>
        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            if (!(token is UserNameSecurityToken userNameToken))
                throw new InvalidOperationException("Expecting UserNameSecurityToken, received: " + typeof(SecurityToken));

            if (Configuration == null)
                throw new InvalidOperationException("Configuration is null, unexpected");

            return (new List<ClaimsIdentity> { new ClaimsIdentity(new List<Claim> { new Claim(ClaimsIdentity.DefaultNameClaimType, userNameToken.UserName) }) } ).AsReadOnly();
        }
    }
}