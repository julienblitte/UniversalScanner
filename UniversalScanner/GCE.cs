using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Text.RegularExpressions;

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
            string lines_string;
            string[] lines;             //lines: hostname, mac, port, product, other;
            string product, mac;

            product = "";
            mac = "";
            try
            {
                lines_string = Encoding.UTF8.GetString(data);

                if (lines_string == requestMagic)
                {
                    return;
                }

                lines = Regex.Split(lines_string, "\r\n|\r|\n");

                if (lines.Length >= 3)
                {
                    product = lines[3].Trim();
                    mac = lines[1].Trim();
                }
            }
            catch(Exception)
            {
                product = "Unknown";
            }

            viewer.deviceFound(name, 1, from.Address, product, mac);
        }

    }
}

