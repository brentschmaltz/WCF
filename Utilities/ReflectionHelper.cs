// ----------------------------------------------------------------------------
// Copyright (C) 2008 Microsoft Corporation, All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Reflection;

namespace WCFSecurityUtilities
{
    
    public static class ReflectionHelper
    {
        const string SecPrefix = "System.ServiceModel.Security.";
        const string SecProtocolPrefix = "System.ServiceModel.Security.";
        const string SecTokenPrefix = "System.ServiceModel.Security.Tokens.";
        const string ChannelPrefix = "System.ServiceModel.Channels.";
        const string IdentityModelPrefix = "System.IdentityModel.";

        const BindingFlags createInstanceFlags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags getMethodFlags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags invokeMethodFlags = BindingFlags.Instance | BindingFlags.InvokeMethod | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags invokeStaticMethodFlags = BindingFlags.Static | BindingFlags.InvokeMethod | BindingFlags.Public | BindingFlags.NonPublic;

        const BindingFlags getFieldFlags = BindingFlags.GetField | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags getStaticFieldFlags = BindingFlags.GetField | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags getPropertyFlags = BindingFlags.GetProperty | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags getStaticPropertyFlags = BindingFlags.GetProperty | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags setFieldFlags = BindingFlags.SetField | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags setStaticFieldFlags = BindingFlags.SetField | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags setPropertyFlags = BindingFlags.SetProperty | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        const BindingFlags setStaticPropertyFlags = BindingFlags.SetProperty | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

        static readonly Assembly indigoAssembly = typeof(System.ServiceModel.Channels.Message).Assembly;
        static readonly Assembly identityModelAssembly = typeof(System.IdentityModel.Tokens.SecurityToken).Assembly;
        static readonly Assembly identityModelSelectorAssembly = typeof(System.IdentityModel.Selectors.AudienceUriMode).Assembly;


        public static readonly string IndigoAssemblyName = indigoAssembly.FullName;

        public static Assembly IndigoAssembly
        {
            get { return indigoAssembly; }
        }

        public static Type GetType(string typeName)
        {
            return IndigoAssembly.GetType(typeName);
        }

        public static Type GetTypeTokenSec(string unqualifiedTypeName)
        {
            return GetType(SecTokenPrefix + unqualifiedTypeName);
        }

        public static Type GetTypeSec(string unqualifiedTypeName)
        {
            return GetType(SecPrefix + unqualifiedTypeName);
        }

        public static Type GetTypeSecProtocol(string unqualifiedTypeName)
        {
            return GetType(SecProtocolPrefix + unqualifiedTypeName);
        }

        public static Type GetTypeIdentityModel(string unqualifiedTypeName)
        {
            return identityModelAssembly.GetType(IdentityModelPrefix + unqualifiedTypeName);
        }

        public static Type GetTypeIdentityModelSelector(string qualifiedTypeName)
        {
            return identityModelSelectorAssembly.GetType(qualifiedTypeName);
        }

        public static object New(string typeName, params object[] args)
        {
            return CheckNew(IndigoAssembly.CreateInstance(typeName, false, createInstanceFlags, null, args , null, null), typeName);
        }

        public static object New(Assembly assembly, string typeName, params object[] args)
        {
            return CheckNew(assembly.CreateInstance(typeName, false, createInstanceFlags, null, args, null, null), typeName);
        }

        public static object NewGenericType(string typeName, params string[] genericParams)
        {
            string genericTypeName = typeName + "`" + genericParams.Length;
            Type genericType = IndigoAssembly.GetType(genericTypeName);
            if (genericType == null)
            {
                genericType = Type.GetType(genericTypeName);
            }
            Type[] genericParamTypes = new Type[genericParams.Length];
            int i = 0;
            foreach (string param in genericParams)
            {
                // We assume the params are also types defined in IndigoAssembley.
                genericParamTypes[i] = IndigoAssembly.GetType(param);
                if (genericParamTypes[i] == null)
                {
                    genericParamTypes[i] = Type.GetType(param);
                }
                ++i;
            }

            Type completeType = genericType.MakeGenericType(genericParamTypes);

            return Activator.CreateInstance(completeType);
        }

        public static object NewSec(string unqualifiedTypeName, params object[] args)
        {
            return New(SecPrefix + unqualifiedTypeName, args);
        }

        public static object NewIdentityModel(string unqualifiedTypeName, params object[] args)
        {
            return New(identityModelAssembly, IdentityModelPrefix + unqualifiedTypeName, args);
        }

        public static object NewSecProtocol(string unqualifiedTypeName, params object[] args)
        {
            return New(SecProtocolPrefix + unqualifiedTypeName, args);
        }

        public static object NewSecToken(string unqualifiedTypeName, params object[] args)
        {
            return New(SecTokenPrefix + unqualifiedTypeName, args);
        }

        public static object NewChannel(string unqualifiedTypeName, params object[] args)
        {
            return New(ChannelPrefix + unqualifiedTypeName, args);
        }

        public static object New(Type type, params object[] args)
        {
            return CheckNew(Activator.CreateInstance(type, createInstanceFlags, null, args, null, null), type.FullName);
        }

        public static T New<T>(params object[] args)
        {
            Type type = typeof(T);
            return (T) CheckNew(Activator.CreateInstance(type, createInstanceFlags, null, args, null, null), type.FullName);
        }

        static object CheckNew(object instance, string typeName)
        {
            if (instance == null)
            {
                throw new Exception(string.Format("Unable to create instance of type '{0}'", typeName));
            }
            return instance;
        }

        public static object Call(object instance, string methodName, params object[] args)
        {
            return instance.GetType().InvokeMember(methodName, invokeMethodFlags, null, instance, args);
        }

        public static object Call(Type type, object instance, string methodName, params object[] args)
        {
            return type.InvokeMember(methodName, invokeMethodFlags, null, instance, args);
        }

        public static object CallStatic(Type type, string methodName, params object[] args)
        {
            return type.InvokeMember(methodName, invokeStaticMethodFlags, null, null, args);
        }

        public static object CallStatic(string typeName, string methodName, params object[] args)
        {
            return CallStatic(GetType(typeName), methodName, args);
        }

        public static object CallStaticTokenSec(string unqualifiedTypeName, string methodName, params object[] args)
        {
            return CallStatic(GetTypeTokenSec(unqualifiedTypeName), methodName, args);
        }

        public static object CallStaticSec(string unqualifiedTypeName, string methodName, params object[] args)
        {
            return CallStatic(GetTypeSec(unqualifiedTypeName), methodName, args);
        }

        public static object CallStaticSecProtocol(string unqualifiedTypeName, string methodName, params object[] args)
        {
            return CallStatic(GetTypeSecProtocol(unqualifiedTypeName), methodName, args);
        }

        public static object CallStaticIdentityModel(string unqualifiedTypeName, string methodName, params object[] args)
        {
            return CallStatic(GetTypeIdentityModel(unqualifiedTypeName), methodName, args);
        }

        public static object GetField(object instance, string fieldName)
        {
            return instance.GetType().InvokeMember(fieldName, getFieldFlags, null, instance, null);
        }

        public static object GetField(Type type, object instance, string fieldName)
        {
            return type.InvokeMember(fieldName, getFieldFlags, null, instance, null);
        }

        public static object GetStaticField(Type typeName, string fieldName)
        {
            return typeName.InvokeMember(fieldName, getStaticFieldFlags, null, null, null);
        }

        public static object GetStaticField(string typeName, string fieldName)
        {
            return GetType(typeName).InvokeMember(fieldName, getStaticFieldFlags, null, null, null);
        }

        public static object GetStaticFieldSec(string unqualifiedTypeName, string fieldName)
        {
            return GetTypeSec(unqualifiedTypeName).InvokeMember(fieldName, getStaticFieldFlags, null, null, null);
        }

        public static object GetStaticFieldSecProtocol(string unqualifiedTypeName, string fieldName)
        {
            return GetTypeSecProtocol(unqualifiedTypeName).InvokeMember(fieldName, getStaticFieldFlags, null, null, null);
        }

        public static object GetStaticFieldIdentityModel(string unqualifiedTypeName, string fieldName)
        {
            return GetTypeIdentityModel(unqualifiedTypeName).InvokeMember(fieldName, getStaticFieldFlags, null, null, null);
        }

        public static object SetField(object instance, string fieldName, object value)
        {
            return instance.GetType().InvokeMember(fieldName, setFieldFlags, null, instance, new object[] {value});
        }

        public static object SetStaticField(string typeName, string fieldName, object value)
        {
            return GetType(typeName).InvokeMember(fieldName, setStaticFieldFlags, null, null, new object[] { value });
        }

        public static object SetStaticFieldIdentityModel(string unqualifiedTypeName, string fieldName, object value)
        {
            return GetTypeIdentityModel(unqualifiedTypeName).InvokeMember(fieldName, setStaticFieldFlags, null, null, new object[] { value });
        }

        public static object SetStaticFieldSec(string unqualifiedTypeName, string fieldName, object value)
        {
            return GetTypeSec(unqualifiedTypeName).InvokeMember(fieldName, setStaticFieldFlags, null, null, new object[] { value });
        }

        public static object SetStaticFieldSecProtocol(string unqualifiedTypeName, string fieldName, object value)
        {
            return GetTypeSecProtocol(unqualifiedTypeName).InvokeMember(fieldName, setStaticFieldFlags, null, null, new object[] { value });
        }

        public static object GetProperty(object instance, string propertyName)
        {
            return instance.GetType().InvokeMember(propertyName, getPropertyFlags, null, instance, null);
        }

        public static object GetProperty(Type type, object instance, string propertyName)
        {
            return type.InvokeMember(propertyName, getPropertyFlags, null, instance, null);
        }

        public static object GetStaticPropertyIdentityModel(string unqualifiedTypeName, string propertyName)
        {
            return GetTypeIdentityModel(unqualifiedTypeName).InvokeMember(propertyName, getStaticPropertyFlags, null, null, null);
        }
        public static object GetStaticProperty(string typeName, string propertyName)
        {
            return GetType(typeName).InvokeMember(propertyName, getStaticPropertyFlags, null, null, null);
        }

        public static object GetStaticPropertySec(string unqualifiedTypeName, string propertyName)
        {
            return GetTypeSec(unqualifiedTypeName).InvokeMember(propertyName, getStaticPropertyFlags, null, null, null);
        }

        public static object GetStaticPropertySecProtocol(string unqualifiedTypeName, string propertyName)
        {
            return GetTypeSecProtocol(unqualifiedTypeName).InvokeMember(propertyName, getStaticPropertyFlags, null, null, null);
        }

        public static object SetProperty(object instance, string propertyName, object value)
        {
            return instance.GetType().InvokeMember(propertyName, setPropertyFlags, null, instance, new object[] {value});
        }

        public static object SetStaticProperty(string typeName, string propertyName, object value)
        {
            return GetType(typeName).InvokeMember(propertyName, setStaticPropertyFlags, null, null, new object[] {value});
        }

        public static object SetStaticPropertySec(string unqualifiedTypeName, string propertyName, object value)
        {
            return GetTypeSec(unqualifiedTypeName).InvokeMember(propertyName, setStaticPropertyFlags, null, null, new object[] {value});
        }

        public static object SetStaticPropertySecProtocol(string unqualifiedTypeName, string propertyName, object value)
        {
            return GetTypeSec(unqualifiedTypeName).InvokeMember(propertyName, setStaticPropertyFlags, null, null, new object[] { value });
        }

        public static object GetAccessor(object instance, int index)
        {
            return instance.GetType().InvokeMember("Item", getPropertyFlags, null, instance, new object[] {index});
        }

        public static object SetAccessor(object instance, int index, object value)
        {
            return instance.GetType().InvokeMember("Item", setPropertyFlags, null, instance, new object[] {index, value});
        }
    }
}
