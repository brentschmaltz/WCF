using System;
using System.IO;
using System.Net.Security;
using System.Runtime.Serialization;
using System.Security.Principal;
using System.ServiceModel;
using System.Threading;

namespace WCFSecurityUtilities
{
    [DataContract]
    public class MyCustomType
    {
        [DataMember]
        int x;

        public MyCustomType()
        {
        }

        public MyCustomType(int x)
        {
            this.x = x;
        }
    }

    [ServiceContract]
    public interface IRequestReplyWithDataContractCustomType
    {
        [OperationContract]
        string SendString(MyCustomType message);

        [OperationContract]
        string SendString2(MyCustomType message);

    }

    [ServiceBehavior]
    public class RequestReplyWithDataContractOnCustomType : IRequestReplyWithDataContractCustomType
    {
        [OperationBehavior]
        public string SendString(MyCustomType message)
        {
            IIdentity identity = OperationContext.Current.ServiceSecurityContext.PrimaryIdentity;
            return "Thanks, from Service (SendString)";
        }

        [OperationBehavior]
        public string SendString2(MyCustomType message)
        {
            return "Thanks, from Service (SendString2)";
        }

    }

    [ServiceContract]
    public interface IAsyncRequestReply
    {
        [OperationContract(AsyncPattern = true)]
        IAsyncResult BeginSendString( string message, AsyncCallback callback, object state );
        string EndSendString( IAsyncResult result );
    }

    public class AsyncRequestReply : IAsyncRequestReply
    {
        #region IAsyncRequestReply Members

        public IAsyncResult BeginSendString( string message, AsyncCallback callback, object state )
        {
            return new CompletedAsyncResult<string>(string.Format("AsyncRequestReply.BeginSendString: You said: {0}" + message), callback, state);
        }

        public string EndSendString( IAsyncResult r )
        {
            CompletedAsyncResult<string> result = r as CompletedAsyncResult<string>;
            Console.WriteLine("AsyncRequestReply.EndSendString");
            return result.Data;
        }

        #endregion

        class CompletedAsyncResult<T> : IAsyncResult
        {
            T data;
            object state;

            public CompletedAsyncResult( T data, AsyncCallback callback, object state )
            {
                this.data = data;
                this.state = state;

                if (callback != null)
                    callback(this);
            }

            public T Data
            {
                get { return data; }
            }

            #region IAsyncResult Members

            public object AsyncState
            {
                get { return state; }
            }

            public WaitHandle AsyncWaitHandle
            {
                get { throw new Exception("The method or operation is not implemented."); }
            }

            public bool CompletedSynchronously
            {
                get { return false; }
            }

            public bool IsCompleted
            {
                get { return true; }
            }

            #endregion
        }
    }

    [ServiceContract(Namespace = "http://Microsoft.WCF.Samples/IMSMQ")]
    public interface IOneWayRequestEncryptAndSign
    {
        [OperationContract(IsOneWay = true, ProtectionLevel = ProtectionLevel.EncryptAndSign)]
        void SendString(string message);

        [OperationContract(IsOneWay = true, ProtectionLevel = ProtectionLevel.EncryptAndSign)]
        void BuyItem(string item, int dollars);
    }

    [ServiceContract(ProtectionLevel=ProtectionLevel.None)]
    public interface IOneWayRequestNoProtection
    {
        [OperationContract(IsOneWay = true)]
        void SendString(string message);

        [OperationContract(IsOneWay = true)]
        void BuyItem(string item, int dollars);
    }


    [ServiceBehavior]
    public class OneWayRequestEncryptAndSign : IOneWayRequestEncryptAndSign
    {
        static int numStringMessages = 0;

        [OperationBehavior]
        public void SendString(string message)
        {
            if (numStringMessages == 0)
            {
                Console.WriteLine("Service received first messages time: '{0}'", DateTime.UtcNow);
            }

            numStringMessages++;

            if ((numStringMessages % 2500) == 0)
            {
                Console.WriteLine("Service received 2500 messages time: '{0}', Total: '{1}", DateTime.UtcNow, numStringMessages);
            }
        }

        [OperationBehavior]
        public void BuyItem(string item, int dollars)
        {
            return;
        }
    }

    [ServiceBehavior]
    public class OneWayRequestNoProtection : IOneWayRequestNoProtection
    {
        static int numStringMessages = 0;

        [OperationBehavior]
        public void SendString(string message)
        {
            if (numStringMessages == 0)
            {
                Console.WriteLine("Service received first messages time: '{0}'", DateTime.UtcNow);
            }

            numStringMessages++;

            if ((numStringMessages % 2500) == 0)
            {
                Console.WriteLine("Service received 2500 messages time: '{0}', Total: '{1}", DateTime.UtcNow, numStringMessages);
            }

            return;
        }

        [OperationBehavior]
        public void BuyItem(string item, int dollars)
        {
            return;
        }
    }
    
    //[Serializable]
    [DataContract(Name = "WSTrustConstants.SoapFaultDetails.UserAccountPasswordExpiredFault", Namespace = "WSTrustConstants.NamespaceURI")]
    public class UserAccountPasswordExpiredFault
    {
        string _passwordChangeEndpoint;
        string _userAccountName;

        public UserAccountPasswordExpiredFault()
        {
        }

        public UserAccountPasswordExpiredFault( string passwordChangeEndpoint, string userAccountName )
        {
            _passwordChangeEndpoint = passwordChangeEndpoint;
            _userAccountName = userAccountName;
        }

        [DataMember(IsRequired = true)]
        public string PasswordChangeEndpoint
        {
            get { return _passwordChangeEndpoint; }
            set { this._passwordChangeEndpoint = value; }
        }

        [DataMember(IsRequired = true)]
        public string UserAccountName
        {
            get { return _userAccountName; }
            set { this._userAccountName = value; }
        }
    }

    [ServiceContract(Namespace = "http://Microsoft.WCF.Samples/IRequestReply", ProtectionLevel = ProtectionLevel.Sign)]
    public interface IRequestReplyFault
    {
        [OperationContract(Action = "foo")]
        [FaultContract(typeof(UserAccountPasswordExpiredFault))]
        string SendString( string message );

        [OperationContract(Action = "BuyItem", Name = "BuyItem")]
        [FaultContract(typeof(UserAccountPasswordExpiredFault))]
        bool BuyItem( string item, int dollars );
    }

    [ServiceContract( Namespace = "http://Ideas/IRequestReply", ProtectionLevel=ProtectionLevel.EncryptAndSign)]
    public interface IRequestReply
    {
        [OperationContract(Action = "IRequestReply.SendString")]
        string SendString( string message );

        [OperationContract(Action = "IRequestReply.BuyItem")]
        bool BuyItem( string item, int dollars );
    }

    [ServiceBehavior]
    public class RequestReplyFault : IRequestReplyFault
    {
        [OperationBehavior]
        public string SendString( string message )
        {
            string outbound = string.Format("Service received: {0}", message);

            Console.WriteLine("Service received: '{0}'", message);
            Console.WriteLine("Service sending: '{0}'", outbound);

            return outbound;
        }

        [OperationBehavior]
        public bool BuyItem( string item, int dollars )
        {
            string outbound = string.Format("Service received: item: {0}, dollars: {1}", item, dollars);

            Console.WriteLine("Service received: '{0}'", outbound);
            Console.WriteLine("Service sending: '{0}'", outbound);

            return true;
        }
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

        [OperationBehavior]
        public bool BuyItem( string item, int dollars )
        {
            string outbound = string.Format( "Service received: item: {0}, dollars: {1}", item, dollars );

            Console.WriteLine( "Service received: '{0}'", outbound );
            Console.WriteLine( "Service sending: '{0}'", outbound );

            return true;
        }
    }

    [ServiceContract(Namespace = "http://Microsoft.WCF.Samples/IRequestReply")]
    public interface IRequestReplyWithDeviceClaims
    {
        [OperationContract(Action = "foo")]
        string SendString(string message);

        [OperationContract(Action = "BuyItem", Name = "BuyItem")]
        bool BuyItem(string item, int dollars);
    }

    [ServiceBehavior]
    public class RequestReplyWithDeviceClaims : IRequestReplyWithDeviceClaims
    {
        [OperationBehavior]
        public string SendString(string message)
        {
            string outbound = string.Format("Service received: {0}", message);

            Console.WriteLine("Service received: '{0}'", message);
            Console.WriteLine("Service sending: '{0}'", outbound);

            return outbound;
        }

        [OperationBehavior]
        public bool BuyItem(string item, int dollars)
        {
            string outbound = string.Format("Service received: item: {0}, dollars: {1}", item, dollars);

            Console.WriteLine("Service received: '{0}'", outbound);
            Console.WriteLine("Service sending: '{0}'", outbound);

            return true;
        }
    }

    [ServiceContract(Namespace = "http://Microsoft.WCF.Samples/IRequestReply")]
    public interface IStreamRequestReply
    {
        [OperationContract]
        void SendStream(Stream message);

        [OperationContract]
        Stream ReturnStream(string fileName);
    }

    [ServiceBehavior]
    public class StreamRequestReply : IStreamRequestReply
    {
        [OperationBehavior]
        public void SendStream(Stream streamIn)
        {
            Stream memoryStream = new MemoryStream();
            bool eof = false;
            while (!eof)
            {
                int messageByte = streamIn.ReadByte();
                if (messageByte == -1)
                {
                    eof = true;
                    memoryStream.Seek(0, 0);
                }
                else
                {
                    memoryStream.WriteByte((byte)messageByte);
                }
            }

            return;
        }

        [OperationBehavior]
        public Stream ReturnStream(string fileName)
        {
            FileStream fs = new FileStream(fileName, FileMode.Open);
            return fs;
        }
    }
}

