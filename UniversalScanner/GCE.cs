using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.Drawing;

/*
 * @description: UniversalScanner discovery protocol
 */

namespace UniversalScanner
{
    class GCE : ScanEngine
    {
        private const int port = 30303;

        private readonly string requestMagic = "Discover GCE Devices";

        public override int color
        {
            get
            {
                return Color.DarkGreen.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "GCE";
            }
        }
        public GCE()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
        }

        public override void scan()
        {
#if DEBUG
            selfTest();
#endif
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return Encoding.UTF8.GetBytes(requestMagic);
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            viewer.deviceFound(name, 1, from.Address, "Unknown", "Unknown");
        }

    }
}

