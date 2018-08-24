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
using System.ServiceModel.Channels;

namespace IssuerSerialKeyInfo
{
    /// <summary>
    /// Base channel class that uses an ChannelMessageInterceptor
    /// </summary>
    class InterceptingChannelBase<TChannel> : ChannelBase where TChannel : class, IChannel
    {
        protected InterceptingChannelBase(
            ChannelManagerBase manager, MessageModifier interceptor, TChannel innerChannel)
            : base(manager)
        {
            Interceptor = interceptor ?? throw new ArgumentNullException(nameof(interceptor));
            InnerChannel = innerChannel ?? throw new ArgumentNullException(nameof(innerChannel));
        }

        public MessageModifier Interceptor { get; private set; }

        protected TChannel InnerChannel
        {
            get; set;
        }

        public override T GetProperty<T>()
        {
            T baseProperty = base.GetProperty<T>();
            if (baseProperty != null)
            {
                return baseProperty;
            }

            return InnerChannel.GetProperty<T>();
        }

        protected override void OnAbort()
        {
            InnerChannel.Abort();
        }

        protected override IAsyncResult OnBeginClose(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannel.BeginClose(timeout, callback, state);
        }

        protected override IAsyncResult OnBeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return InnerChannel.BeginOpen(timeout, callback, state);
        }

        protected override void OnClose(TimeSpan timeout)
        {
            InnerChannel.Close(timeout);
        }

        protected override void OnEndClose(IAsyncResult result)
        {
            InnerChannel.EndClose(result);
        }

        protected override void OnEndOpen(IAsyncResult result)
        {
            InnerChannel.EndOpen(result);
        }

        protected override void OnOpen(TimeSpan timeout)
        {
            InnerChannel.Open(timeout);
        }

        protected void OnReceive(ref Message message)
        {
            Interceptor.OnReceive(ref message);
        }
    }
}
