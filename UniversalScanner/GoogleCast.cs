using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class GoogleCast : ScanEngine
    {
        protected mDNS dnsBroker;
        private static readonly string domain = "_googlecast._tcp.local";

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
                return "Google";
            }
        }

        public GoogleCast()
        {
            dnsBroker = mDNS.getInstance();

            dnsBroker.registerDomain(domain, googlecastDeviceFound);
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            throw new NotImplementedException();
        }

        public override void scan()
        {
            dnsBroker.scan(domain, mDNSType.TYPE_PTR);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return (new byte[0]);
        }

        public void googlecastDeviceFound(string domainFilter, mDNSAnswer[] answers)
        {
            IPAddress ipv4, ipv6;
            string deviceType, deviceID;

            ipv4 = null;
            ipv6 = null;
            deviceType = "unknown";
            deviceID = "unknown";
            foreach (var a in answers)
            {
                switch (a.Type)
                {
                    case mDNSType.TYPE_A:
                        if (ipv4 == null)
                        {
                            ipv4 = a.data.typeA;
                        }
                        break;
                    case mDNSType.TYPE_AAAA:
                        if (ipv6 == null)
                        {
                            ipv6 = a.data.typeA;
                        }
                        break;
                    case mDNSType.TYPE_ANY:
                        break;
                    case mDNSType.TYPE_PTR:
                        if (deviceType == null)
                        {
                            deviceType = a.data.typePTR;
                            if (deviceType.Contains('.'))
                            {
                                deviceType = deviceType.Split('.')[0];
                            }
                        }
                        break;
                    case mDNSType.TYPE_SRV:
                        break;
                    case mDNSType.TYPE_TXT:
                        if (a.data.typeTXT[0].Contains('='))
                        {
                            for(int i=0; i < a.data.typeTXT.Length; i++)
                            {
                                string[] keyPair;

                                keyPair = a.data.typeTXT[i].Split('=');
                                if (keyPair.Length == 2)
                                {
                                    if (keyPair[0].Trim() == "fn")
                                    {
                                        deviceID = keyPair[1].Trim();
                                    }
                                    else if (keyPair[0].Trim() == "md")
                                    {
                                        deviceType = keyPair[1].Trim();
                                    }
                                }
                            }
                        }
                        break;
                }
            }

            if (ipv4 != null)
            {
                viewer.deviceFound(name, 1, ipv4, deviceType, deviceID);
            }
            if (ipv6 != null)
            {
                viewer.deviceFound(name, 1, ipv6, deviceType, deviceID);
            }
        }
    }
}
