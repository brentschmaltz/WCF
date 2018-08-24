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
    class InterceptingChannelListener<TChannel> : ChannelListenerBase<TChannel> where TChannel : class, IChannel
    {
        public InterceptingChannelListener(MessageModifier interceptor, BindingContext context)
        {
            Interceptor = interceptor ?? throw new ArgumentNullException(nameof(interceptor));
            InnerChannelListener = context.BuildInnerChannelListener<TChannel>() ?? throw new InvalidOperationException(
                    "InterceptingChannelListener requires an inner IChannelListener.");
        }

        public IChannelListener<TChannel> InnerChannelListener
        {
            get; private set;
        }

        public MessageModifier Interceptor
        {
            get; private set;
        }

        public override Uri Uri => InnerChannelListener.Uri;

        public override T GetProperty<T>()
        {
            return base.GetProperty<T>() ?? InnerChannelListener.GetProperty<T>();
        }

        protected override void OnOpen(TimeSpan timeout)
        {
            InnerChannelListener.Open(timeout);
        }

        protected override IAsyncResult OnBeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannelListener.BeginOpen(timeout, callback, state);
        }

        protected override void OnEndOpen(IAsyncResult result)
        {
            InnerChannelListener.EndOpen(result);
        }

        protected override void OnClose(TimeSpan timeout)
        {
            InnerChannelListener.Close(timeout);
        }

        protected override IAsyncResult OnBeginClose(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannelListener.BeginClose(timeout, callback, state);
        }

        protected override void OnEndClose(IAsyncResult result)
        {
            InnerChannelListener.EndClose(result);
        }

        protected override void OnAbort()
        {
            InnerChannelListener.Abort();
        }

        protected override TChannel OnAcceptChannel(TimeSpan timeout)
        {
            return WrapChannel(InnerChannelListener.AcceptChannel(timeout));
        }

        protected override IAsyncResult OnBeginAcceptChannel(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannelListener.BeginAcceptChannel(timeout, callback, state);
        }

        protected override TChannel OnEndAcceptChannel(IAsyncResult result)
        {
            return WrapChannel(InnerChannelListener.EndAcceptChannel(result));
        }

        protected override bool OnWaitForChannel(TimeSpan timeout)
        {
            return InnerChannelListener.WaitForChannel(timeout);
        }

        protected override IAsyncResult OnBeginWaitForChannel(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannelListener.BeginWaitForChannel(timeout, callback, state);
        }

        protected override bool OnEndWaitForChannel(IAsyncResult result)
        {
            return InnerChannelListener.EndWaitForChannel(result);
        }

        TChannel WrapChannel(TChannel innerChannel)
        {
            if (innerChannel == null)
            {
                return null;
            }

            if (typeof(TChannel) == typeof(IInputChannel))
            {
                return (TChannel)(object)new InterceptingInputChannel<IInputChannel>(this, Interceptor, (IInputChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IReplyChannel))
            {
                return (TChannel)(object)new InterceptingReplyChannel(this, (IReplyChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IDuplexChannel))
            {
                return (TChannel)(object)new InterceptingDuplexChannel(this, Interceptor, (IDuplexChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IInputSessionChannel))
            {
                return (TChannel)(object)new InterceptingInputSessionChannel(this,
                    (IInputSessionChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IReplySessionChannel))
            {
                return (TChannel)(object)new InterceptingReplySessionChannel(this,
                    (IReplySessionChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IDuplexSessionChannel))
            {
                return (TChannel)(object)new InterceptingDuplexSessionChannel(this, Interceptor, 
                    (IDuplexSessionChannel)innerChannel);
            }

            // Cannot wrap this channel.
            return innerChannel;
        }

        class InterceptingReplyChannel : InterceptingChannelBase<IReplyChannel>, IReplyChannel
        {
            public InterceptingReplyChannel(
                InterceptingChannelListener<TChannel> listener, IReplyChannel innerChannel)
                : base(listener, listener.Interceptor, innerChannel)
            {
                // empty
            }

            public EndpointAddress LocalAddress => InnerChannel.LocalAddress;

            public RequestContext ReceiveRequest()
            {
                return ReceiveRequest(DefaultReceiveTimeout);
            }

            public RequestContext ReceiveRequest(TimeSpan timeout)
            {
                RequestContext requestContext;
                while (true)
                {
                    requestContext = InnerChannel.ReceiveRequest(timeout);
                    if (ProcessRequestContext(ref requestContext))
                    {
                        break;
                    }
                }

                return requestContext;
            }

            public IAsyncResult BeginReceiveRequest(AsyncCallback callback, object state)
            {
                return BeginReceiveRequest(DefaultReceiveTimeout, callback, state);
            }

            public IAsyncResult BeginReceiveRequest(TimeSpan timeout, AsyncCallback callback, object state)
            {
                ReceiveRequestAsyncResult result = new ReceiveRequestAsyncResult(this, timeout, callback, state);
                result.Begin();
                return result;
            }

            public RequestContext EndReceiveRequest(IAsyncResult result)
            {
                return ReceiveRequestAsyncResult.End(result);
            }

            public bool TryReceiveRequest(TimeSpan timeout, out RequestContext requestContext)
            {
                bool result;

                while (true)
                {
                    result = InnerChannel.TryReceiveRequest(timeout, out requestContext);
                    if (!result || ProcessRequestContext(ref requestContext))
                    {
                        break;
                    }
                }

                return result;
            }

            public IAsyncResult BeginTryReceiveRequest(TimeSpan timeout, AsyncCallback callback, object state)
            {
                var result = new TryReceiveRequestAsyncResult(this, timeout, callback, state);
                result.Begin();
                return result;
            }

            public bool EndTryReceiveRequest(IAsyncResult result, out RequestContext requestContext)
            {
                return TryReceiveRequestAsyncResult.End(result, out requestContext);
            }

            public bool WaitForRequest(TimeSpan timeout)
            {
                return InnerChannel.WaitForRequest(timeout);
            }

            public IAsyncResult BeginWaitForRequest(TimeSpan timeout, AsyncCallback callback, object state)
            {
                return InnerChannel.BeginWaitForRequest(timeout, callback, state);
            }

            public bool EndWaitForRequest(IAsyncResult result)
            {
                return InnerChannel.EndWaitForRequest(result);
            }

            bool ProcessRequestContext(ref RequestContext requestContext)
            {
                if (requestContext == null)
                    return true;

                Message m = requestContext.RequestMessage;
                Message originalMessage = m;               
                OnReceive(ref m);
                if (m != null || originalMessage == null)
                {
                    requestContext = new InterceptingRequestContext(this, requestContext, m);
                }
                else
                {
                    requestContext.Abort();
                    requestContext = null;
                }
                
                return requestContext != null;
            }

            abstract class ReceiveRequestAsyncResultBase : AsyncResult
            {
                RequestContext _requestContext;
                InterceptingReplyChannel _channel;
                AsyncCallback _onReceive;

                protected ReceiveRequestAsyncResultBase(InterceptingReplyChannel channel,
                    AsyncCallback callback, object state)
                    : base(callback, state)
                {
                    this._channel = channel;
                    this._onReceive = new AsyncCallback(OnReceive);
                }

                protected RequestContext RequestContext
                {
                    get { return this._requestContext; }
                }

                public void Begin()
                {
                    IAsyncResult result = BeginReceiveRequest(_onReceive, null);
                    if (result.CompletedSynchronously)
                    {
                        if (HandleReceiveComplete(result))
                        {
                            base.Complete(true);
                        }
                    }
                }

                protected abstract IAsyncResult BeginReceiveRequest(AsyncCallback callback, object state);
                protected abstract RequestContext EndReceiveRequest(IAsyncResult result);

                bool HandleReceiveComplete(IAsyncResult result)
                {
                    while (true)
                    {
                        this._requestContext = EndReceiveRequest(result);
                        if (_channel.ProcessRequestContext(ref _requestContext))
                        {
                            return true;
                        }

                        // try again
                        result = BeginReceiveRequest(_onReceive, null);
                        if (!result.CompletedSynchronously)
                        {
                            return false;
                        }
                    }
                }

                void OnReceive(IAsyncResult result)
                {
                    if (result.CompletedSynchronously)
                    {
                        return;
                    }

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

                public IReplyChannel InnerChannel { get; protected set; }

                public TimeSpan Timeout { get; protected set; }

            }

            class TryReceiveRequestAsyncResult : ReceiveRequestAsyncResultBase
            {
                TimeSpan _timeout;
                bool _returnValue;

                public TryReceiveRequestAsyncResult(InterceptingReplyChannel channel, TimeSpan timeout,
                    AsyncCallback callback, object state)
                    : base(channel, callback, state)
                {
                    InnerChannel = channel.InnerChannel;
                    this._timeout = timeout;
                }

                protected override IAsyncResult BeginReceiveRequest(AsyncCallback callback, object state)
                {
                    return InnerChannel.BeginTryReceiveRequest(this._timeout, callback, state);
                }

                protected override RequestContext EndReceiveRequest(IAsyncResult result)
                {
                    RequestContext requestContext;
                    this._returnValue = InnerChannel.EndTryReceiveRequest(result, out requestContext);
                    return requestContext;
                }

                public static bool End(IAsyncResult result, out RequestContext requestContext)
                {
                    TryReceiveRequestAsyncResult thisPtr = AsyncResult.End<TryReceiveRequestAsyncResult>(result);
                    requestContext = thisPtr.RequestContext;
                    return thisPtr._returnValue;
                }
            }

            class ReceiveRequestAsyncResult : ReceiveRequestAsyncResultBase
            {
                public ReceiveRequestAsyncResult(InterceptingReplyChannel channel, TimeSpan timeout, AsyncCallback callback, object state)
                    : base(channel, callback, state)
                {
                    InnerChannel = channel.InnerChannel;
                    Timeout = timeout;
                }

                protected override IAsyncResult BeginReceiveRequest(AsyncCallback callback, object state)
                {
                    return InnerChannel.BeginReceiveRequest(Timeout, callback, state);
                }

                protected override RequestContext EndReceiveRequest(IAsyncResult result)
                {
                    return InnerChannel.EndReceiveRequest(result);
                }

                public static RequestContext End(IAsyncResult result)
                {
                    ReceiveRequestAsyncResult thisPtr = AsyncResult.End<ReceiveRequestAsyncResult>(result);
                    return thisPtr.RequestContext;
                }
            }

            class InterceptingRequestContext : RequestContext
            {
                InterceptingReplyChannel _channel;
                RequestContext _innerContext;
                Message _message;

                public InterceptingRequestContext(InterceptingReplyChannel channel, RequestContext innerContext)
                {
                    this._channel = channel;
                    this._innerContext = innerContext;
                }

                public InterceptingRequestContext(InterceptingReplyChannel channel, RequestContext innerContext, Message message)
                {
                    this._channel = channel;
                    this._innerContext = innerContext;
                    _message = message;
                }

                public override Message RequestMessage
                {
                    get
                    {
                        return _message;
                        //return this.innerContext.RequestMessage;
                    }
                }

                public override void Abort()
                {
                    this._innerContext.Abort();
                }

                public override IAsyncResult BeginReply(Message message, AsyncCallback callback, object state)
                {
                    return BeginReply(message, _channel.DefaultSendTimeout, callback, state);
                }

                public override IAsyncResult BeginReply(Message message, TimeSpan timeout, AsyncCallback callback, object state)
                {
                    return this._innerContext.BeginReply(message, timeout, callback, state);
                }

                public override void Close()
                {
                    this._innerContext.Close();
                }

                public override void Close(TimeSpan timeout)
                {
                    this._innerContext.Close(timeout);
                }

                protected override void Dispose(bool disposing)
                {
                    try
                    {
                        if(disposing)
                             ((IDisposable)this._innerContext).Dispose();
                    }
                    finally
                    {
                        base.Dispose(disposing);
                    }
                }

                public override void EndReply(IAsyncResult result)
                {
                    this._innerContext.EndReply(result);
                }

                public override void Reply(Message message)
                {
                    Reply(message, _channel.DefaultSendTimeout);
                }

                public override void Reply(Message message, TimeSpan timeout)
                {
                    this._innerContext.Reply(message, timeout);
                }
            }
        }

        class InterceptingInputSessionChannel : InterceptingInputChannel<IInputSessionChannel>, IInputSessionChannel
        {
            IInputSessionChannel _innerSessionChannel;

            public InterceptingInputSessionChannel(
                InterceptingChannelListener<TChannel> listener, IInputSessionChannel innerChannel)
                : base(listener, listener.Interceptor, innerChannel)
            {
                this._innerSessionChannel = innerChannel;
            }

            public IInputSession Session
            {
                get
                {
                    return this._innerSessionChannel.Session;
                }
            }
        }

        class InterceptingReplySessionChannel : InterceptingReplyChannel, IReplySessionChannel
        {
            IReplySessionChannel innerSessionChannel;

            public InterceptingReplySessionChannel(
                InterceptingChannelListener<TChannel> listener, IReplySessionChannel innerChannel)
                : base(listener, innerChannel)
            {
                this.innerSessionChannel = innerChannel;
            }

            public IInputSession Session
            {
                get
                {
                    return this.innerSessionChannel.Session;
                }
            }
        }       
    }
}
