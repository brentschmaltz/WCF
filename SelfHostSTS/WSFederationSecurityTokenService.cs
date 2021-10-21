//------------------------------------------------------------------------------
//
// Copyright (c) Brent Schmaltz
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.IdentityModel;
using System.IdentityModel.Services;
using System.IO;
using System.Security.Claims;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using System.Web;
using System.Xml.Linq;

namespace SelfHostSTS
{
    /// <summary>
    /// Ws-Federation STS implementation.
    /// </summary>
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single)]
    internal class WSFederationSecurityTokenService : IWSFederationSecurityTokenService
    {
        SelfHostSecurityTokenServiceConfiguration _stsConfiguration;
        SecurityTokenService _securityTokenService;

        public WSFederationSecurityTokenService(SelfHostSecurityTokenServiceConfiguration stsConfiguration)
            : base()
        {
            _stsConfiguration = stsConfiguration;
            _securityTokenService = new SelfHostSecurityTokenService(stsConfiguration);
        }

        /// <summary>
        /// Issues a SignInResponse message that issues a token.
        /// </summary>
        /// <param name="realm">The realm value.</param>
        /// <param name="wctx">The context.</param>
        /// <param name="wct">The wct parameter.</param>
        /// <param name="wreply">The return url.</param>
        /// <returns></returns>
        public Stream Issue(string realm, string wctx, string wct, string wreply, string wreq)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream, Encoding.UTF8);

            string fullRequest = _stsConfiguration.BaseAddress + Port + Constants.WSFedSTSIssue + String.Format(CultureInfo.InvariantCulture, Constants.SignInResponseMessageFormat, realm, HttpUtility.UrlEncode(wctx), wct, wreply, wreq);

            SignInRequestMessage requestMessage = (SignInRequestMessage)WSFederationMessage.CreateFromUri(new Uri(fullRequest));

            ClaimsIdentity identity = new ClaimsIdentity(AuthenticationTypes.Federation);
            ClaimsPrincipal principal = new ClaimsPrincipal(identity);

            SignInResponseMessage responseMessage = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(requestMessage, principal, _securityTokenService);
            responseMessage.Write(writer);

            writer.Flush();
            stream.Position = 0;

            WebOperationContext.Current.OutgoingResponse.ContentType = Constants.ContentType;
            return stream;
        }

        public string Port
        {
            get { return _stsConfiguration.HttpsPort; }
        }

        /// <summary>
        /// Implements the contract that gets the federation metadata.
        /// </summary>
        /// <returns></returns>
        public XElement FederationMetadata()
        {             
            return _stsConfiguration.GetFederationMetadata();
        }
    }
}