//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
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

