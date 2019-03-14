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
using System.ServiceModel;
using System.ServiceModel.Channels;

namespace IssuerSerialKeyInfo
{
    class InterceptingInputChannel<TChannel> : InterceptingChannelBase<TChannel>, IInputChannel
        where TChannel : class, IInputChannel
    {
        public InterceptingInputChannel(
            ChannelManagerBase manager, MessageModifier interceptor, TChannel innerChannel)
            : base(manager, interceptor, innerChannel)
        {
            // empty
        }

        public EndpointAddress LocalAddress
        {
            get
            {
                return InnerChannel.LocalAddress;
            }
        }

        bool ProcessReceivedMessage(ref Message message)
        {
            Message originalMessage = message;
            this.OnReceive(ref message);
            return (message != null || originalMessage == null);
        }

        public Message Receive()
        {
            return Receive(DefaultReceiveTimeout);
        }

        public Message Receive(TimeSpan timeout)
        {
            Message message;
            while (true)
            {
                message = InnerChannel.Receive(timeout);
                if (ProcessReceivedMessage(ref message))
                    break;
            }

            return message;
        }

        public IAsyncResult BeginReceive(AsyncCallback callback, object state)
        {
            return BeginReceive(DefaultReceiveTimeout, callback, state);
        }

        public IAsyncResult BeginReceive(TimeSpan timeout, AsyncCallback callback, object state)
        {
            ReceiveAsyncResult<TChannel> result = new ReceiveAsyncResult<TChannel>(this, timeout, callback, state);
            result.Begin();
            return result;
        }

        public Message EndReceive(IAsyncResult result)
        {
            return ReceiveAsyncResult<TChannel>.End(result);
        }

        public bool TryReceive(TimeSpan timeout, out Message message)
        {
            bool result;
            while (true)
            {
                result = InnerChannel.TryReceive(timeout, out message);
                if (ProcessReceivedMessage(ref message))
                    break;
            }

            return result;
        }

        public IAsyncResult BeginTryReceive(TimeSpan timeout, AsyncCallback callback, object state)
        {
            TryReceiveAsyncResult<TChannel> result = new TryReceiveAsyncResult<TChannel>(this, timeout, callback, state);
            result.Begin();
            return result;
        }

        public bool EndTryReceive(IAsyncResult result, out Message message)
        {
            return TryReceiveAsyncResult<TChannel>.End(result, out message);
        }

        public bool WaitForMessage(TimeSpan timeout)
        {
            return InnerChannel.WaitForMessage(timeout);
        }

        public IAsyncResult BeginWaitForMessage(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannel.BeginWaitForMessage(timeout, callback, state);
        }

        public bool EndWaitForMessage(IAsyncResult result)
        {
            return InnerChannel.EndWaitForMessage(result);
        }

        abstract class ReceiveAsyncResultBase<TInputChannel> : AsyncResult
            where TInputChannel : class, IInputChannel
        {
            Message _message;
            InterceptingInputChannel<TInputChannel> _channel;
            AsyncCallback _onReceive;

            protected ReceiveAsyncResultBase(InterceptingInputChannel<TInputChannel> channel,
                AsyncCallback callback, object state)
                : base(callback, state)
            {
                this._channel = channel;
                this._onReceive = new AsyncCallback(OnReceive);
            }

            protected Message Message
            {
                get { return this._message; }
            }

            public void Begin()
            {
                IAsyncResult result = BeginReceive(_onReceive, null);
                if (result.CompletedSynchronously)
                {
                    if (HandleReceiveComplete(result))
                    {
                        base.Complete(true);
                    }
                }
            }

            protected abstract IAsyncResult BeginReceive(AsyncCallback callback, object state);
            protected abstract Message EndReceive(IAsyncResult result);

            bool HandleReceiveComplete(IAsyncResult result)
            {
                while (true)
                {
                    this._message = EndReceive(result);
                    if (_channel.ProcessReceivedMessage(ref _message))
                    {
                        return true;
                    }

                    // try again
                    result = BeginReceive(_onReceive, null);
                    if (!result.CompletedSynchronously)
                    {
                        return false;
                    }
                }
            }

            void OnReceive(IAsyncResult result)
            {
                if (result.CompletedSynchronously)
                    return;

                bool completeSelf = false;
                Exception completeException = null;
                try
                {
                    completeSelf = HandleReceiveComplete(result);
                }
                catch (Exception e)
                {
                    completeException = e;
                    completeSelf = true;
                }

                if (completeSelf)
                {
                    base.Complete(false, completeException);
                }
            }
        }

        class TryReceiveAsyncResult<TInputChannel> : ReceiveAsyncResultBase<TInputChannel>
            where TInputChannel : class, IInputChannel
        {
            TimeSpan _timeout;
            bool _returnValue;

            public TryReceiveAsyncResult(InterceptingInputChannel<TInputChannel> channel, TimeSpan timeout,
                AsyncCallback callback, object state)
                : base(channel, callback, state)
            {
                InnerChannel = channel.InnerChannel;
                this._timeout = timeout;
            }

            public TInputChannel InnerChannel { get; set; }

            protected override IAsyncResult BeginReceive(AsyncCallback callback, object state)
            {
                return InnerChannel.BeginTryReceive(this._timeout, callback, state);
            }

            protected override Message EndReceive(IAsyncResult result)
            {
                this._returnValue = InnerChannel.EndTryReceive(result, out Message message);
                return message;
            }

            public static bool End(IAsyncResult result, out Message message)
            {
                TryReceiveAsyncResult<TInputChannel> thisPtr = AsyncResult.End<TryReceiveAsyncResult<TInputChannel>>(result);
                message = thisPtr.Message;
                return thisPtr._returnValue;
            }
        }

        class ReceiveAsyncResult<TInputChannel> : ReceiveAsyncResultBase<TInputChannel>
           where TInputChannel : class, IInputChannel
        {
            public ReceiveAsyncResult(InterceptingInputChannel<TInputChannel> channel, TimeSpan timeout,
                AsyncCallback callback, object state)
                : base(channel, callback, state)
            {
                InnerChannel = channel.InnerChannel;
                Timeout = timeout;
            }

            public TInputChannel InnerChannel { get; set; }

            public TimeSpan Timeout { get; set; }

            protected override IAsyncResult BeginReceive(AsyncCallback callback, object state)
            {
                return InnerChannel.BeginReceive(Timeout, callback, state);
            }

            protected override Message EndReceive(IAsyncResult result)
            {
                return InnerChannel.EndReceive(result);
            }

            public static Message End(IAsyncResult result)
            {
                ReceiveAsyncResult<TInputChannel> thisPtr = AsyncResult.End<ReceiveAsyncResult<TInputChannel>>(result);
                return thisPtr.Message;
            }
        }
    }

    class InterceptingDuplexChannel : InterceptingInputChannel<IDuplexChannel>, IDuplexChannel
    {
        public InterceptingDuplexChannel(
            ChannelManagerBase manager, MessageModifier interceptor, IDuplexChannel innerChannel)
            : base(manager, interceptor, innerChannel)
        {
            // empty
        }

        public EndpointAddress RemoteAddress => InnerChannel.RemoteAddress;

        public Uri Via => InnerChannel.Via;

        public void Send(Message message)
        {
            Send(message, DefaultSendTimeout);
        }

        public void Send(Message message, TimeSpan timeout)
        {
            InnerChannel.Send(message, timeout);
        }

        public IAsyncResult BeginSend(Message message, AsyncCallback callback, object state)
        {
            return BeginSend(message, DefaultSendTimeout, callback, state);
        }

        public IAsyncResult BeginSend(Message message, TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannel.BeginSend(message, timeout, callback, state);
        }

        public void EndSend(IAsyncResult result)
        {
            InnerChannel.EndSend(result);
        }
    }

    class InterceptingDuplexSessionChannel : InterceptingDuplexChannel, IDuplexSessionChannel
    {
        public InterceptingDuplexSessionChannel(
            ChannelManagerBase manager, MessageModifier interceptor, IDuplexSessionChannel innerChannel)
            : base(manager, interceptor, innerChannel)
        {
            InnerSessionChannel = innerChannel;
        }

        public IDuplexSessionChannel InnerSessionChannel { get; set; }

        public IDuplexSession Session => InnerSessionChannel.Session;
    }
}
