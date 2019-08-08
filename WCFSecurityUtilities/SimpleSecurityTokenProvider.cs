
using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;

namespace WCFSecurityUtilities
{
    /// <summary>
    /// Returns the SecurityToken that was passed in the constructor
    /// </summary>
    class SimpleSecurityTokenProvider : SecurityTokenProvider
    {
        SecurityToken _st;

        public SimpleSecurityTokenProvider(SecurityToken st)
        {
            _st = st ?? throw new ArgumentNullException(nameof(st));
        }

        /// <summary>
        /// Just return token
        /// </summary>C:\github\brentschmaltz\WCF\WCFSecurityUtilities\SimpleSecurityTokenProvider.cs
        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            return _st;
        }
    }
}
