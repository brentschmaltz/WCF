using System.IO;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Xml.Linq;

namespace SelfHostSTS
{
    /// <summary>
    /// WS-Federation STS's service contract.
    /// </summary>
    [ServiceContract]
    internal interface IWSFederationSecurityTokenService
    {
        [OperationContract]
        [WebGet(UriTemplate = Constants.UriTemplate)]
        Stream Issue(string realm, string wctx, string wct, string wreply, string wreq);

        [OperationContract]
        [WebGet(UriTemplate = "/" + Constants.FederationMetadataAddress)]
        XElement FederationMetadata(); 
    }
}