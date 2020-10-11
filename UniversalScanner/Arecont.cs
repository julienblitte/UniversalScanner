using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using JulienBlitte;

namespace UniversalScanner
{
    class Arecont : ScanEngine
    {
        private mDNS dnsBroker;
        private static readonly string domain = "_arec._tcp.local";

        public override int color
        {
            get
            {
                return Color.DarkBlue.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Arecont";
            }
        }

        public Arecont()
        {
            dnsBroker = mDNS.getInstance();

            dnsBroker.registerDomain(domain, mdnsReplyReciever);
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            throw new NotImplementedException();
        }

        public void multiScanThread()
        {
            for (int i=0; i < 4; i++)
            {
                if (i > 0) Thread.Sleep(750);
                dnsBroker.scan(domain, mDNSType.TYPE_PTR);
            }
        }

        public override void scan()
        {
            Thread multiScan;
#if DEBUG
            dnsBroker.selfTest("Arecont.selftest");
#endif
            //dnsBroker.scan(domain, mDNSType.TYPE_PTR);

            multiScan = new Thread(multiScanThread);
            multiScan.Start();
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return (new byte[0]);
        }

        public void mdnsReplyReciever(string domainFilter, mDNSAnswer[] answers)
        {
            List<IPAddress> addresses;
            string deviceModel, serial;
            Hashtable variables;

            addresses = new List<IPAddress>();
            variables = new Hashtable();
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
                        foreach (string txt in a.data.typeTXT)
                        {
                            int splitter;

                            splitter = txt.IndexOf('=');
                            if (splitter >= 0)
                            {
                                string name, value;
                                name = txt.Substring(0, splitter);
                                value = txt.Substring(splitter + 1);
                                if (!variables.ContainsKey(name))
                                {
                                    variables.Add(name, value);
                                }
                            }
                        }
                        break;
                }
            }

            if (addresses.Count > 0)
            {
                int splitter;

                if (deviceModel == null) deviceModel = "unknown";

                // method 1: retrieve device model and mac by name                
                splitter = deviceModel.IndexOf('-');
                if (splitter >= 0)
                {
                    if (serial == null)
                    {
                        serial = deviceModel.Substring(splitter+1).Trim();
                    }
                    deviceModel = deviceModel.Substring(0, splitter).Trim();
                }

                // method 2 (more accurate): retrieve device model and mac by variable
                if (variables.ContainsKey("MAC"))
                {
                    string infos;

                    infos = (string)variables["MAC"];
                    splitter = infos.IndexOf('/');
                    if (splitter >= 0)
                    {
                        deviceModel = "AV" + infos.Substring(splitter + 1);
                    }

                    if (serial == null)
                    {
                        splitter = infos.IndexOf('-');
                        if (splitter >= 0)
                        {
                            deviceModel = infos.Substring(0, splitter);
                        }
                    }
                }

                // resolve arecont serial coding
                serial = serial.Replace("AV", "001A07");

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
                        if (!hasNonAutoIPv4 || Config.forceZeroConf)
                        {
                            viewer.deviceFound(protocol, version, ip, deviceModel, serial);
                        }
                    }
                    if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        if (!hasNonAutoIPv6 || Config.forceLinkLocal)
                        {
                            viewer.deviceFound(protocol, version, ip, deviceModel, serial);
                        }
                    }
                }
            }
        }
    }
}
