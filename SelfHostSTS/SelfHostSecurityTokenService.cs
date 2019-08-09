using System;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.ServiceModel;

namespace SelfHostSTS
{
    /// <summary>
    /// A simple SelfHost STS that speaks WSTrust
    /// </summary>
    internal class SelfHostSecurityTokenService : SecurityTokenService
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="configuration"></param>
        public SelfHostSecurityTokenService(SecurityTokenServiceConfiguration configuration)
            : base(configuration)
        {
        }

        /// <summary>
        /// Gets the scope.
        /// </summary>
        /// <param name="principal"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            if (principal == null)
                throw new ArgumentNullException(nameof(principal));

            if (request == null)
                throw new ArgumentNullException(nameof(request));

            if (request.AppliesTo == null)
                throw new FaultException<InvalidProgramException>(new InvalidProgramException("request.AppliesTo cannot be null"), new FaultReason("request.AppliesTo cannot be null"), new FaultCode("AppliesToNull"), "Set Applies To"); 

            if (request.AppliesTo.Uri == null)
                throw new InvalidProgramException("request.AppliesTo.Uri cannot be null");

            if (string.IsNullOrWhiteSpace(request.AppliesTo.Uri.OriginalString))
                throw new InvalidProgramException("request.AppliesTo.Uri.AbsoluteUri cannot be null or only whitespace");

            var scope = new Scope(request.AppliesTo.Uri.OriginalString, SecurityTokenServiceConfiguration.SigningCredentials)
            {
                TokenEncryptionRequired = false,
                //EncryptingCredentials = new X509EncryptingCredentials(SecurityTokenServiceConfiguration.ServiceCertificate),
                SymmetricKeyEncryptionRequired = false
            };

            if (string.IsNullOrEmpty(request.ReplyTo))
                scope.ReplyToAddress = scope.AppliesToAddress;
            else
                scope.ReplyToAddress = request.ReplyTo;

            return scope;
        }

        /// <summary>
        /// Gets the claims for this user.
        /// </summary>
        /// <param name="principal"></param>
        /// <param name="request"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            if (principal == null)
                throw new ArgumentNullException(nameof(principal));

            if (request == null)
                throw new ArgumentNullException(nameof(request));

            if (scope == null)
                throw new ArgumentNullException(nameof(scope));

            var outputIdentity = principal.Identity as ClaimsIdentity;
            if ( request.ActAs != null )
            {
                var currIdentity = outputIdentity;
                foreach (var identity in request.ActAs.GetIdentities())
                {
                    currIdentity.Actor = identity;
                    currIdentity = identity.Actor;
                }
            }

            return outputIdentity;
        }
    }
}