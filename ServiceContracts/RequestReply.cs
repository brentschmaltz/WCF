//-----------------------------------------------------------------------------
// RequestReply
//  - contracts with different ProtectionLevels
// ----------------------------------------------------------------------------

using System;
using System.Net.Security;
using System.ServiceModel;

namespace WcfContracts
{
    [ServiceContract]
    public interface IRequestReply
    {
        [OperationContract()]
        string SendString( string message );
    }

    [ServiceBehavior]
    public class RequestReply : IRequestReply
    {
        [OperationBehavior]
        public string SendString( string message )
        {
            string outbound = string.Format( "Service received: {0}", message );

            Console.WriteLine( "Service received: '{0}'", message );
            Console.WriteLine( "Service sending: '{0}'", outbound );

            return outbound;
        }
    }

    [ServiceContract]
    public interface IRequestReplyEncryptAndSign
    {
        [OperationContract(ProtectionLevel = ProtectionLevel.EncryptAndSign)]
        string SendString(string message);
    }

    [ServiceBehavior]
    public class RequestReplyEncryptAndSign : IRequestReplyEncryptAndSign
    {
        [OperationBehavior]
        public string SendString(string message)
        {
            string outbound = string.Format("Service received: {0}", message);
            Console.WriteLine("Service received: '{0}'", message);
            Console.WriteLine("Service sending: '{0}'", outbound);
            return outbound;
        }
    }


    [ServiceContract]
    public interface IRequestReplySign
    {
        [OperationContract(ProtectionLevel = ProtectionLevel.Sign)]
        string SendString(string message);
    }

    [ServiceBehavior]
    public class RequestReplySign : IRequestReplySign
    {
        [OperationBehavior]
        public string SendString(string message)
        {
            string outbound = string.Format("Service received: {0}", message);

            Console.WriteLine("Service received: '{0}'", message);
            Console.WriteLine("Service sending: '{0}'", outbound);

            return outbound;
        }
    }
}

