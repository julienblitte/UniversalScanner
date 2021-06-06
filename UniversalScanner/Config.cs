using Microsoft.Win32;
using JulienBlitte;

namespace UniversalScanner
{
    public class Config
    {
        private bool enableIPv6;
        private bool forceLinkLocal;
        private bool enableIPv4;
        private bool forceZeroConf;
        private bool forceGenericProtocols;
        private bool debugMode;
        private bool portSharing;
        private bool onvifVerbatim;
        private bool dahuaNetScan;

        public bool EnableIPv6 { get => enableIPv6; set { enableIPv6 = value; updateBool(nameof(enableIPv6), value); }  }
        public bool ForceLinkLocal { get => forceLinkLocal; set { forceLinkLocal = value; updateBool(nameof(forceLinkLocal), value); } }
        public bool EnableIPv4 { get => enableIPv4; set { enableIPv4 = value; updateBool(nameof(enableIPv4), value); } }
        public bool ForceZeroConf { get => forceZeroConf; set { forceZeroConf = value; updateBool(nameof(forceZeroConf), value); } }
        public bool ForceGenericProtocols { get => forceGenericProtocols; set { forceGenericProtocols = value; updateBool(nameof(forceGenericProtocols), value); } }
        public bool DebugMode { get => debugMode; set { debugMode = value; updateBool(nameof(debugMode), value); } }
        public bool PortSharing { get => portSharing; set { portSharing = value; updateBool(nameof(portSharing), value); } }
        public bool OnvifVerbatim { get => onvifVerbatim; set { onvifVerbatim = value; updateBool(nameof(onvifVerbatim), value); } }
        public bool DahuaNetScan { get => dahuaNetScan; set { dahuaNetScan = value; updateBool(nameof(dahuaNetScan), value); } }

        private static readonly string path = @"Software\UniversalScanner";

        private static Config instance;

        private Config()
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

                key.Close();
            }
        }

        public void updateBool(string variable, bool value)
        {
            RegistryKey key;

            key = Registry.CurrentUser.openOrCreate(path);
            if (key != null)
            {
                key.writeBool(variable, value);

                key.Close();
            }
        }

        public static Config getInstance()
        {
            if (instance == null)
            {
                instance = new Config();
            }
            return instance;
        }
    }
}
