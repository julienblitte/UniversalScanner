using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    public static class Config
    {
        private static readonly string enableIPv6Variable = "EnableIPv6";
        private static readonly string forceLinkLocalVariable = "ForceLinkLocal";
        private static readonly string enableIPv4Variable = "EnableIPv4";
        private static readonly string forceZeroConfVariable = "ForceZeroConf";
        private static readonly string forceGenericProtocolsVariable = "ForceGenericProtocols";
        private static readonly string clearOnRescanVariable = "ClearOnRescan";
        private static readonly string showDebugWarningVariable = "ShowDebugWarning";

        public static bool enableIPv6;
        public static bool forceLinkLocal;
        public static bool enableIPv4;
        public static bool forceZeroConf;
        public static bool forceGenericProtocols;
        public static bool clearOnRescan;
        public static bool showDebugWarning;
        
        private static readonly string path = @"Software\UniversalScanner";

        static Config()
        {
            RegistryKey key;

            // default values
            enableIPv6 = false;
            forceLinkLocal = true;
            enableIPv4 = true;
            forceZeroConf = false;
            forceGenericProtocols = false;
            clearOnRescan = false;
            showDebugWarning = true;

            key = Registry.CurrentUser.openOrCreate(path);
            if (key != null)
            {
                enableIPv6 = key.readBool(enableIPv6Variable, enableIPv6);
                key.writeBool(enableIPv6Variable, enableIPv6);

                forceLinkLocal = key.readBool(forceLinkLocalVariable, forceLinkLocal);
                key.writeBool(forceLinkLocalVariable, forceLinkLocal);
                
                enableIPv4 = key.readBool(enableIPv4Variable, enableIPv4);
                key.writeBool(enableIPv4Variable, enableIPv4);
                
                forceZeroConf = key.readBool(forceZeroConfVariable, forceZeroConf);
                key.writeBool(forceZeroConfVariable, forceZeroConf);
                
                forceGenericProtocols = key.readBool(forceGenericProtocolsVariable, forceGenericProtocols);
                key.writeBool(forceGenericProtocolsVariable, forceGenericProtocols);
                
                clearOnRescan = key.readBool(clearOnRescanVariable, clearOnRescan);
                key.writeBool(clearOnRescanVariable, clearOnRescan);
                
                showDebugWarning = key.readBool(showDebugWarningVariable, showDebugWarning);
                key.writeBool(showDebugWarningVariable, showDebugWarning);
            }
        }
    }
}
