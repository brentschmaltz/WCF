//-----------------------------------------------------------------------------
// RequestReply
//  - contracts with different ProtectionLevels
// ----------------------------------------------------------------------------

using System.ServiceModel;

namespace WcfContracts
{
    [ServiceContract]
    public interface IRequestReply
    {
        [OperationContract()]
        string SendString( string message );
    }
}

