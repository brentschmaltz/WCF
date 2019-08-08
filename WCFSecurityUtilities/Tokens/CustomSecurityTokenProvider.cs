using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace WCFSecurityUtilities
{
    public class CustomSecurityTokenProvider : SecurityTokenProvider
    {
        CustomSecurityToken customSecurityToken;
        int keysize;
        static RandomNumberGenerator random;
        object Lock;

        public CustomSecurityTokenProvider(int keysize)
        {
            this.Lock = new object();
            this.keysize = keysize;
        }

        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            if (this.customSecurityToken == null)
            {
                lock (this.Lock)

                    if (this.customSecurityToken == null)
                    {
                        byte[] bytes = new Byte[keysize];
                        random = new RNGCryptoServiceProvider();
                        random.GetBytes(bytes);
                        this.customSecurityToken = new CustomSecurityToken(Guid.NewGuid().ToString(), bytes);

                        //
                        // TODO - [brentsch] build random security key
                        //
                    }
            }

            return this.customSecurityToken;
        }
    }
}
