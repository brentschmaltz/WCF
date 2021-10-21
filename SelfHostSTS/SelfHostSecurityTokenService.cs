using System;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.ServiceModel;
using RST = System.IdentityModel.Protocols.WSTrust.RequestSecurityToken;
using RSTR = System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse;

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
        /// <param name="selfHostSecurityTokenServiceConfiguration"></param>
        public SelfHostSecurityTokenService(SelfHostSecurityTokenServiceConfiguration selfHostSecurityTokenServiceConfiguration)
            : base(selfHostSecurityTokenServiceConfiguration)
        {
            SelfHostSecurityTokenServiceConfiguration = selfHostSecurityTokenServiceConfiguration;
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

            var ski = new SecurityKeyIdentifier();
            ski.Add(new X509IssuerSerialKeyIdentifierClause(SelfHostSecurityTokenServiceConfiguration.RelyingPartyCertificate));
            var scope = new Scope(request.AppliesTo.Uri.OriginalString, SecurityTokenServiceConfiguration.SigningCredentials)
            {
                EncryptingCredentials = new X509EncryptingCredentials(SelfHostSecurityTokenServiceConfiguration.RelyingPartyCertificate, new SecurityKeyIdentifier(new X509IssuerSerialKeyIdentifierClause(SelfHostSecurityTokenServiceConfiguration.RelyingPartyCertificate))),
                SymmetricKeyEncryptionRequired = true,
                TokenEncryptionRequired = false
            };

            if (string.IsNullOrEmpty(request.ReplyTo))
                scope.ReplyToAddress = scope.AppliesToAddress;
            else
                scope.ReplyToAddress = request.ReplyTo;

            return scope;
        }

        /// <summary>
        /// Gets the proof token.
        /// </summary>
        /// <param name="request">The incoming token request.</param>
        /// <param name="scope">The scope instance encapsulating information about the relying party.</param>
        /// <returns>The newly created proof decriptor that could be either asymmetric proof descriptor or symmetric proof descriptor or null in the bearer token case.</returns>
        protected override ProofDescriptor GetProofToken(RST request, Scope scope)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            if (scope == null)
                throw new ArgumentNullException(nameof(scope));

            EncryptingCredentials requestorWrappingCredentials = GetRequestorProofEncryptingCredentials(request);

            if (scope.EncryptingCredentials != null &&
                  !(scope.EncryptingCredentials.SecurityKey is AsymmetricSecurityKey))
                throw new SecurityTokenException("scope.EncryptingCredentials != null && !(scope.EncryptingCredentials.SecurityKey is AsymmetricSecurityKey))");

            EncryptingCredentials targetWrappingCredentials = scope.EncryptingCredentials;

            //
            // Generate the proof key
            //
            string keyType = (string.IsNullOrEmpty(request.KeyType)) ? KeyTypes.Symmetric : request.KeyType;
            ProofDescriptor result = null;

            if (StringComparer.Ordinal.Equals(keyType, KeyTypes.Asymmetric))
            {
                //
                // Asymmetric is only supported with UseKey
                //
                if (request.UseKey == null)
                    throw new InvalidRequestException("request.UseKey == null");

                result = new AsymmetricProofDescriptor(request.UseKey.SecurityKeyIdentifier);
            }
            else if (StringComparer.Ordinal.Equals(keyType, KeyTypes.Symmetric))
            {
                //
                // Only support PSHA1. Overwrite STS to support custom key algorithm
                //
                if (request.ComputedKeyAlgorithm != null && !StringComparer.Ordinal.Equals(request.ComputedKeyAlgorithm, ComputedKeyAlgorithms.Psha1))
                    throw new RequestFailedException("request.ComputedKeyAlgorithm != null && !StringComparer.Ordinal.Equals(request.ComputedKeyAlgorithm, ComputedKeyAlgorithms.Psha1");
                //
                // We must wrap the symmetric key inside the security token
                //
                if (requestorWrappingCredentials == null && scope.SymmetricKeyEncryptionRequired)
                    throw new RequestFailedException("requestorWrappingCredentials == null && scope.SymmetricKeyEncryptionRequired");

                //
                // We are encrypting the proof token or the server entropy using client's encrypting credential if present,
                // which will be used to encrypt the key during serialization.
                // Otherwise, we can only send back the key in plain text. However, the current implementation of 
                // WSTrustServiceContract sets the rst.ProofEncryption = null by default. Therefore, the server entropy
                // or the proof token will be sent in plain text no matter the client's entropy is sent encrypted or unencrypted.
                //
                if (request.KeySizeInBits.HasValue)
                {
                    if (request.Entropy != null)
                    {
                        result = new SymmetricProofDescriptor(request.KeySizeInBits.Value, targetWrappingCredentials, requestorWrappingCredentials,
                                                               request.Entropy.GetKeyBytes(), request.EncryptWith);
                    }
                    else
                    {
                        result = new SymmetricProofDescriptor(request.KeySizeInBits.Value, targetWrappingCredentials);
                    }
                }
                else
                {
                    throw new RequestFailedException("!request.KeySizeInBits.HasValue");
                }
            }
            else if (StringComparer.Ordinal.Equals(keyType, KeyTypes.Bearer))
            {
                //
                // Intentionally empty, no proofDescriptor
                //
            }

            return result;
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

        //
        // Summary:
        //     Gets the requestor's proof encrypting credentials.
        //
        // Parameters:
        //   request:
        //     A System.IdentityModel.Protocols.WSTrust.RequestSecurityToken that represents
        //     the incoming token request (RST).
        //
        // Returns:
        //     An System.IdentityModel.Tokens.EncryptingCredentials object that represents the
        //     requestor’s encrypting credentials.
        //
        // Exceptions:
        //   T:System.ArgumentNullException:
        //     request is null.
        protected override EncryptingCredentials GetRequestorProofEncryptingCredentials(RequestSecurityToken request)
        {
            return new X509EncryptingCredentials(SelfHostSecurityTokenServiceConfiguration.RelyingPartyCertificate);
        }

        public SelfHostSecurityTokenServiceConfiguration SelfHostSecurityTokenServiceConfiguration { get; }
    }
}