//----------------------------------------------------------------
// Code was copied from  WCF_SAMPLES - https://msdn.microsoft.com/en-us/library/dd483346(v=vs.110).aspx
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

using System;
using System.Collections.ObjectModel;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;

namespace Microsoft.Samples.ServiceModel
{
    public class EndpointValidateBehavior : IServiceBehavior
    {
        private Collection<ServiceEndpoint> _endpoints;
        private BindingParameterCollection _bindingParameters;
        private string _messageProtectionOrder;

        public EndpointValidateBehavior(string messageProtectionOrder)
        {
            _messageProtectionOrder = messageProtectionOrder;
        }

        public void AddBindingParameters(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase, System.Collections.ObjectModel.Collection<ServiceEndpoint> endpoints, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {
            _endpoints = endpoints;
            _bindingParameters = bindingParameters;
        }

        public void ApplyDispatchBehavior(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase)
        {
        }

        // The validation process will scan each endpoint to see if the SecurityBindingElements have MessageProtectionOrder of EncryptBeforeSign
        public void Validate(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase)
        {
            var bindingErrors = new StringBuilder();
            foreach (ServiceEndpoint endpoint in serviceDescription.Endpoints)
            {
                BindingElementCollection bindingElements = endpoint.Binding.CreateBindingElements();
                var sbe = bindingElements.Find<SecurityBindingElement>();
                if (sbe != null)
                {
                    var ssbe = sbe as SymmetricSecurityBindingElement;
                    if (ssbe != null)
                    {
                        if (ssbe.MessageProtectionOrder.ToString() != _messageProtectionOrder)
                            bindingErrors.Append($"{Environment.NewLine}BindingName: {endpoint.Name}, MessageProtectionOrder: {ssbe.MessageProtectionOrder}.");
                    }

                    var asbe = sbe as AsymmetricSecurityBindingElement;
                    if (asbe != null)
                    {
                        if (asbe.MessageProtectionOrder.ToString() != _messageProtectionOrder)
                            bindingErrors.Append($"{Environment.NewLine}BindingName: {endpoint.Name}, MessageProtectionOrder: {asbe.MessageProtectionOrder}.");
                    }
                }
            }

            if (bindingErrors.Length > 0)
                throw new Exception($"Some bindings do not have MessgeProtectionOrder set to: '{MessageProtectionOrder.EncryptBeforeSign}': {Environment.NewLine}{bindingErrors}");
        }
    }
}
