//----------------------------------------------------------------
// Code was copied from  WCF_SAMPLES - https://msdn.microsoft.com/en-us/library/dd483346(v=vs.110).aspx
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

using System;
using System.Configuration;
using System.ServiceModel.Configuration;

namespace Microsoft.Samples.ServiceModel
{
    class EndpointValidateElement : BehaviorExtensionElement
    {
        protected override object CreateBehavior()
        {
            return new EndpointValidateBehavior(MessageProtectionOrder);
        }

        public override Type BehaviorType
        {
            get { return typeof(EndpointValidateBehavior); }
        }

        [ConfigurationProperty("messageProtectionOrder")]
        public string MessageProtectionOrder
        {
            get { return (string)this["messageProtectionOrder"]; }
            set { this["messageProtectionOrder"] = value; }
        }
    }
}
