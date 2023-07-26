using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using JulienBlitte;

namespace UniversalScanner
{
    class Axis : ScanEngine
    {
        private mDNS dnsBroker;
        private static readonly string[] domains = { "_axis-nvr._tcp.local", "_axis-video._tcp.local" };

        public override int color
        {
            get
            {
                return 0x806000;
            }
        }
        public override string name
        {
            get
            {
                return "Axis";
            }
        }

        public Axis()
        {
            dnsBroker = mDNS.getInstance();

            foreach(var d in domains)
            {
                dnsBroker.registerDomain(d, axisDeviceFound);
            }
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            throw new NotImplementedException();
        }

        public override void scan()
        {
#if DEBUG
            dnsBroker.selfTest("Axis.selftest");
#endif
            foreach (var d in domains)
            {
                dnsBroker.scan(d, mDNSType.TYPE_PTR);
            }
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return (new byte[0]);
        }

        public void axisDeviceFound(string domainFilter, mDNSAnswer[] answers)
        {
            List <IPAddress> addresses;
            string deviceModel, serial;

            addresses = new List<IPAddress>();
            deviceModel = null;
            serial = null;
            foreach (var a in answers)
            {
                switch (a.Type)
                {
                    case mDNSType.TYPE_A:
                        addresses.Add(a.data.typeA);
                        break;
                    case mDNSType.TYPE_AAAA:
                        addresses.Add(a.data.typeAAAA);
                        break;
                    case mDNSType.TYPE_ANY:
                        break;
                    case mDNSType.TYPE_PTR:
                        if (deviceModel == null)
                        {
                            int splitter;

                            deviceModel = a.data.typePTR;
                            splitter = deviceModel.IndexOf('.');
                            if (splitter >= 0)
                            {
                                deviceModel = deviceModel.Substring(0, splitter);
                            }
                        }
                        break;
                    case mDNSType.TYPE_SRV:
                        break;
                    case mDNSType.TYPE_TXT:
                        if (serial == null)
                        {
                            int splitter;

                            serial = a.data.typeTXT[0];
                            splitter = serial.IndexOf('=');
                            if (splitter >= 0)
                            {
                                serial = serial.Substring(splitter + 1);
                            }
                        }
                        break;
                }
            }

            if (addresses.Count > 0)
            {
                if (deviceModel == null) deviceModel = "unknown";

                int modelMacSplitter = deviceModel.IndexOf(" - ");
                if (modelMacSplitter >= 0)
                {
                    if (serial == null)
                    {
                        serial = deviceModel.Substring(modelMacSplitter + 3).Trim();
                    }
                    deviceModel = deviceModel.Substring(0, modelMacSplitter).Trim();
                }

                if (serial == null) serial = "unknown";

                deviceFound(name, 1, addresses, deviceModel, serial);
            }
        }

        private void deviceFound(string protocol, int version, List<IPAddress> addresses, string deviceModel, string serial)
        {
            bool hasNonAutoIPv4, hasNonAutoIPv6;

            if (viewer == null)
                return;

            hasNonAutoIPv4 = false;
            hasNonAutoIPv6 = false;
            foreach (var ip in addresses)
            {
                if (!ip.isAutoConf())
                {
                    viewer.deviceFound(protocol, version, ip, deviceModel, serial);
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        hasNonAutoIPv4 = true;
                    }
                    if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        hasNonAutoIPv6 = true;
                    }
                }
            }

            // handle auto-conf addresses
            foreach (var ip in addresses)
            {
                if (ip.isAutoConf())
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        if (!hasNonAutoIPv4 || Config.getInstance().ForceZeroConf)
                        {
                            viewer.deviceFound(protocol, version, ip, deviceModel, serial);
                        }
                    }
                    if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        if (!hasNonAutoIPv6 || Config.getInstance().ForceLinkLocal)
                        {
                            viewer.deviceFound(protocol, version, ip, deviceModel, serial);
                        }
                    }
                }
            }
        }
    }
}
