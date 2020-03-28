using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class Axis : ScanEngine
    {
        protected mDNS dnsBroker;
        private static readonly string[] domains = { "_axis-nvr._tcp.local", "_axis-video._tcp.local" };

        public override int color
        {
            get
            {
                return Color.DarkGoldenrod.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Axis";
            }
        }

        public Axis(mDNS broker)
        {
            dnsBroker = broker;

            foreach(var d in domains)
            {
                dnsBroker.registerDomainTypeA(d, axisDeviceFound);
            }
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            throw new NotImplementedException();
        }

        public override void scan()
        {
            foreach (var d in domains)
            {
                dnsBroker.scan(d, mDNS.mDNSType.TYPE_A);
            }
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return (new byte[0]);
        }

        public void axisDeviceFound(string domainFilter, IPAddress address)
        {
            viewer.deviceFound(name, address.ToString(), "axisType", "axisSN");
        }
    }
}
