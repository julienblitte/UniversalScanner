using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.Drawing;
using JulienBlitte;

/*
 * @description: UniversalScanner discovery protocol
 */

namespace UniversalScanner
{
    class Hid : ScanEngine
    {
        private const int port = 4070;
        private readonly string request = "discover;013;";

        public override int color
        {
            get
            {
                return 0x0000549B;
            }
        }
        public override string name
        {
            get
            {
                return "Hid";
            }
        }
        public Hid()
        {
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
            return Encoding.UTF8.GetBytes(request);
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            viewer.deviceFound(name, 1, from.Address, "Unknown", "Unknown");
        }

    }
}

