using Microsoft.Win32;
using JulienBlitte;

namespace UniversalScanner
{
    public static class Config
    {
        public static bool enableIPv6;
        public static bool forceLinkLocal;
        public static bool enableIPv4;
        public static bool forceZeroConf;
        public static bool forceGenericProtocols;
        public static bool debugMode;
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
            debugMode = false;
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
                
                debugMode = key.readBool(nameof(debugMode), debugMode);
                key.writeBool(nameof(debugMode), debugMode);

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
