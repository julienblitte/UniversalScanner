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
        public static bool enableIPv6;
        public static bool forceLinkLocal;
        public static bool enableIPv4;
        public static bool forceZeroConf;
        public static bool forceGenericProtocols;
        public static bool clearOnRescan;
        public static bool showDebugWarning;
        public static bool portSharing;
        public static bool onvifVerbatim;
        public static bool dahuaNetScan;

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
            portSharing = true;
            onvifVerbatim = false;
            dahuaNetScan = false;

            key = Registry.CurrentUser.openOrCreate(path);
            if (key != null)
            {
                enableIPv6 = key.readBool(nameof(enableIPv6), enableIPv6);
                key.writeBool(nameof(enableIPv6), enableIPv6);

                forceLinkLocal = key.readBool(nameof(forceLinkLocal), forceLinkLocal);
                key.writeBool(nameof(forceLinkLocal), forceLinkLocal);
                
                enableIPv4 = key.readBool(nameof(enableIPv4), enableIPv4);
                key.writeBool(nameof(enableIPv4), enableIPv4);
                
                forceZeroConf = key.readBool(nameof(forceZeroConf), forceZeroConf);
                key.writeBool(nameof(forceZeroConf), forceZeroConf);
                
                forceGenericProtocols = key.readBool(nameof(forceGenericProtocols), forceGenericProtocols);
                key.writeBool(nameof(forceGenericProtocols), forceGenericProtocols);
                
                clearOnRescan = key.readBool(nameof(clearOnRescan), clearOnRescan);
                key.writeBool(nameof(clearOnRescan), clearOnRescan);
                
                showDebugWarning = key.readBool(nameof(showDebugWarning), showDebugWarning);
                key.writeBool(nameof(showDebugWarning), showDebugWarning);

                portSharing = key.readBool(nameof(portSharing), portSharing);
                key.writeBool(nameof(portSharing), portSharing);

                onvifVerbatim = key.readBool(nameof(onvifVerbatim), onvifVerbatim);
                key.writeBool(nameof(onvifVerbatim), onvifVerbatim);

                dahuaNetScan = key.readBool(nameof(dahuaNetScan), dahuaNetScan);
                key.writeBool(nameof(dahuaNetScan), dahuaNetScan);
            }
        }
    }
}
