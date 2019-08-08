using System;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;

namespace WCFSecurityUtilities
{
    class CustomSecurityAuthorizationPolicy : IAuthorizationPolicy
    {
        String id = Guid.NewGuid().ToString();

        public CustomSecurityAuthorizationPolicy()
        {
        }

        public string Id
        {
            get { return this.id; }
        }

        public ClaimSet Issuer 
        { 
            get { return ClaimSet.System; } 
        }

        public bool Evaluate(EvaluationContext evaluationContext, ref object state)
        {
            evaluationContext.AddClaimSet(this, ClaimSet.System);
            return true;
        }
    }
}
