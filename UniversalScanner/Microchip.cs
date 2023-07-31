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
    class Microchip : ScanEngine
    {
        private const int port = 30303;

        private readonly string requestMagic = "Discover GCE Devices";

        public override int color
        {
            get
            {
                return Color.Red.ToArgb();
            }
        }
        public override UInt16[] getUsedPort()
        {
            return new UInt16[] { port };
        }
        public override string name
        {
            get
            {
                return "Microchip";
            }
        }
        public Microchip()
        {

        }
        public override void listen()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
        }
        public override void scan()
        {
#if DEBUG
            selfTest();
            selfTest("GCE.selftest");
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
            string manufacturer;

            product = "";
            mac = "";
            manufacturer = name;
            try
            {
                lines_string = Encoding.UTF8.GetString(data);

                if (lines_string == requestMagic)
                {
                    return;
                }

                lines = Regex.Split(lines_string, "\r\n|\r|\n");

                if (lines.Length >= 4)
                {
                    mac = lines[1].Trim();
                    product = lines[3].Trim();
                    manufacturer = "GCE";
                }
                else if (lines.Length >= 2)
                {
                    product = lines[0].Trim();
                    mac = lines[1].Trim();
                }
            }
            catch (Exception)
            {
                product = "Unknown";
            }

            viewer.deviceFound(manufacturer, 1, from.Address, product, mac);
        }

    }
}

