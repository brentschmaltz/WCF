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
    /// <summary>
    /// ChannelFactory that performs message Interception
    /// </summary>
    class InterceptingChannelFactory<TChannel> : ChannelFactoryBase<TChannel>
    {
        public InterceptingChannelFactory(MessageModifier interceptor, BindingContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            Interceptor = interceptor ?? throw new ArgumentNullException(nameof(interceptor));
            InnerChannelFactory = context.BuildInnerChannelFactory<TChannel>() ?? 
                throw new InvalidOperationException("InterceptingChannelFactory requires an inner IChannelFactory.");
        }

        IChannelFactory<TChannel> InnerChannelFactory { get; set; }

        public MessageModifier Interceptor
        {
            get; private set;
        }

        public override T GetProperty<T>()
        {
            T baseProperty = base.GetProperty<T>();
            return baseProperty ?? InnerChannelFactory.GetProperty<T>();
        }

        protected override void OnOpen(TimeSpan timeout)
        {
            InnerChannelFactory.Open(timeout);
        }

        protected override IAsyncResult OnBeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannelFactory.BeginOpen(timeout, callback, state);
        }

        protected override void OnEndOpen(IAsyncResult result)
        {
            InnerChannelFactory.EndOpen(result);
        }

        protected override void OnAbort()
        {
            base.OnAbort();
            InnerChannelFactory.Abort();
        }

        protected override void OnClose(TimeSpan timeout)
        {
            TimeoutHelper timeoutHelper = new TimeoutHelper(timeout);
            base.OnClose(timeoutHelper.RemainingTime());
            InnerChannelFactory.Close(timeoutHelper.RemainingTime());
        }

        protected override IAsyncResult OnBeginClose(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return new ChainedAsyncResult(timeout, callback, state, base.OnBeginClose, base.OnEndClose, InnerChannelFactory.BeginClose, InnerChannelFactory.EndClose);
        }

        protected override void OnEndClose(IAsyncResult result)
        {
            ChainedAsyncResult.End(result);
        }

        protected override TChannel OnCreateChannel(EndpointAddress to, Uri via)
        {
            TChannel innerChannel = InnerChannelFactory.CreateChannel(to, via);
            if (typeof(TChannel) == typeof(IOutputChannel))
            {
                return (TChannel)(object)new InterceptingOutputChannel(this, (IOutputChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IRequestChannel))
            {
                return (TChannel)(object)new InterceptingRequestChannel(this, (IRequestChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IDuplexChannel))
            {
                return (TChannel)(object)new InterceptingDuplexChannel(this, Interceptor, (IDuplexChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IOutputSessionChannel))
            {
                return (TChannel)(object)new InterceptingOutputSessionChannel(this, (IOutputSessionChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IRequestSessionChannel))
            {
                return (TChannel)(object)new InterceptingRequestSessionChannel(this,
                    (IRequestSessionChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IDuplexSessionChannel))
            {
                return (TChannel)(object)new InterceptingDuplexSessionChannel(this, Interceptor, (IDuplexSessionChannel)innerChannel);
            }

            throw new InvalidOperationException();
        }

        class InterceptingOutputChannel : InterceptingChannelBase<IOutputChannel>, IOutputChannel
        {
            public InterceptingOutputChannel(InterceptingChannelFactory<TChannel> factory, IOutputChannel innerChannel)
                : base(factory, factory.Interceptor, innerChannel)
            {
                // empty
            }

            public EndpointAddress RemoteAddress => InnerChannel.RemoteAddress;

            public Uri Via => InnerChannel.Via;

            public IAsyncResult BeginSend(Message message, AsyncCallback callback, object state)
            {
                return BeginSend(message, DefaultSendTimeout, callback, state);
            }

            public IAsyncResult BeginSend(Message message, TimeSpan timeout, AsyncCallback callback, object state)
            {
                return new SendAsyncResult(this, message, timeout, callback, state);
            }

            public void EndSend(IAsyncResult result)
            {
                SendAsyncResult.End(result);
            }

            public void Send(Message message)
            {
                Send(message, DefaultSendTimeout);
            }

            public void Send(Message message, TimeSpan timeout)
            {
                if (message != null)
                    InnerChannel.Send(message, timeout);
            }

            class SendAsyncResult : AsyncResult
            {
                AsyncCallback sendCallback = new AsyncCallback(OnSend);
                
                public SendAsyncResult(IOutputChannel channel, Message message, TimeSpan timeout, AsyncCallback callback, object state) 
                    : base(callback, state)
                {
                    if (message != null)
                    {
                        Channel = channel;
                        IAsyncResult sendResult = channel.BeginSend(message, timeout, sendCallback, this);
                        if (!sendResult.CompletedSynchronously)
                            return;

                        CompleteSend(sendResult);
                    }

                    base.Complete(true);
                }

                private IOutputChannel Channel { get; set; }

                void CompleteSend(IAsyncResult result)
                {
                    Channel.EndSend(result);
                }

                static void OnSend(IAsyncResult result)
                {
                    if (result.CompletedSynchronously)
                        return;

                    var thisPtr = (SendAsyncResult)result.AsyncState;
                    Exception completionException = null;

                    try
                    {
                        thisPtr.CompleteSend(result);
                    }
                    catch (Exception e)
                    {
                        completionException = e;
                    }

                    thisPtr.Complete(false, completionException);
                }

                public static void End(IAsyncResult result)
                {
                    AsyncResult.End<SendAsyncResult>(result);
                }
            }
        }

        class InterceptingRequestChannel : InterceptingChannelBase<IRequestChannel>, IRequestChannel
        {
            public InterceptingRequestChannel(InterceptingChannelFactory<TChannel> factory, IRequestChannel innerChannel)
                : base(factory, factory.Interceptor, innerChannel)
            {
            }

            public EndpointAddress RemoteAddress => InnerChannel.RemoteAddress;

            public Uri Via => InnerChannel.Via;

            public IAsyncResult BeginRequest(Message message, AsyncCallback callback, object state)
            {
                return BeginRequest(message, this.DefaultSendTimeout, callback, state);
            }

            public IAsyncResult BeginRequest(Message message, TimeSpan timeout, AsyncCallback callback, object state)
            {
                return new RequestAsyncResult(this, message, timeout, callback, state);
            }

            public Message EndRequest(IAsyncResult result)
            {
                Message reply = RequestAsyncResult.End(result);
                OnReceive(ref reply);
                return reply;
            }

            public Message Request(Message message)
            {
                return Request(message, this.DefaultSendTimeout);
            }

            public Message Request(Message message, TimeSpan timeout)
            {
                Message reply = null;
                if (message != null)
                    reply = InnerChannel.Request(message);

                OnReceive(ref reply);
                return reply;
            }

            class RequestAsyncResult : AsyncResult
            {
                Message replyMessage;
                InterceptingRequestChannel channel;
                AsyncCallback requestCallback = new AsyncCallback(OnRequest);

                public RequestAsyncResult(InterceptingRequestChannel channel, Message message, TimeSpan timeout, AsyncCallback callback, object state)
                    : base(callback, state)
                {
                    if (message != null)
                    {
                        this.channel = channel;

                        IAsyncResult requestResult = channel.InnerChannel.BeginRequest(message, timeout, requestCallback, this);
                        if (!requestResult.CompletedSynchronously)
                        {
                            return;
                        }

                        CompleteRequest(requestResult);
                    }

                    base.Complete(true);
                }

                void CompleteRequest(IAsyncResult result)
                {
                    replyMessage = channel.InnerChannel.EndRequest(result);
                }

                static void OnRequest(IAsyncResult result)
                {
                    if (result.CompletedSynchronously)
                    {
                        return;
                    }

                    RequestAsyncResult thisPtr = (RequestAsyncResult)result.AsyncState;
                    Exception completionException = null;

                    try
                    {
                        thisPtr.CompleteRequest(result);
                    }
                    catch (Exception e)
                    {
                        completionException = e;
                    }

                    thisPtr.Complete(false, completionException);
                }

                public static Message End(IAsyncResult result)
                {
                    RequestAsyncResult thisPtr = AsyncResult.End<RequestAsyncResult>(result);
                    return thisPtr.replyMessage;
                }
            }

        }

        class InterceptingOutputSessionChannel : InterceptingOutputChannel, IOutputSessionChannel
        {
            public InterceptingOutputSessionChannel(
                InterceptingChannelFactory<TChannel> factory, IOutputSessionChannel innerChannel)
                : base(factory, innerChannel)
            {
                InnerChannel = innerChannel;
            }

            public IOutputSession Session => ((IOutputSessionChannel)InnerChannel).Session;
        }

        class InterceptingRequestSessionChannel : InterceptingRequestChannel, IRequestSessionChannel
        {
            public InterceptingRequestSessionChannel(
                InterceptingChannelFactory<TChannel> factory, IRequestSessionChannel innerChannel)
                : base(factory, innerChannel)
            {
                InnerSessionChannel = innerChannel;
            }

            public IRequestSessionChannel InnerSessionChannel { get; set; }

            public IOutputSession Session => InnerSessionChannel.Session;
        }
    }
}
