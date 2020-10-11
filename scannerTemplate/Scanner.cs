using System;
using System.Collections.Generic;
using System.Linq;
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
    class Scanner : ScanEngine
    {
        private const int port = 1234;
        private readonly string multicastIP = "239.255.255.250";

        private readonly string requestMagic = "discover";

        public override int color
        {
            get
            {
                return Color.Black.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Scanner";
            }
        }
        public Scanner()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
        }

        public override void scan()
        {
#if DEBUG
            // sample selfttest content: reply/127.1.2.3/Sample/0123456789
            selfTest();
#endif
            sendMulticast(IPAddress.Parse(multicastIP), port);
            //sendBroadcast(port);
        }

        // request format: "discover/<filter>"
        public override byte[] sender(IPEndPoint dest)
        {
            return Encoding.UTF8.GetBytes(String.Format("{0}/*", requestMagic));
        }

        // request format: "reply/<ipv4>/<model>/<serial>"
        public override void reciever(IPEndPoint from, byte[] data)
        {
            string text;
            string deviceIP, deviceModel, deviceSerial;
            string[] fields;
            IPAddress ip;

            text = Encoding.UTF8.GetString(data);
            fields = text.Split('/');

            if (fields.Length >= 1)
            {
                if (fields[0] == requestMagic)
                {
                    return;
                }
            }

            deviceIP = from.Address.ToString();
            if (fields.Length >= 2)
            {
                deviceIP = fields[1];
            }

            deviceModel = "Unknown";
            if (fields.Length >= 3)
            {
                deviceModel = fields[2];
            }

            deviceSerial = "Unknown";
            if (fields.Length >= 4)
            {
                deviceSerial = fields[3];
            }

            if (IPAddress.TryParse(deviceIP, out ip))
            {
                viewer.deviceFound(name, 1, ip, deviceModel, deviceSerial);
            }
            else
            {
                viewer.deviceFound(name, 1, from.Address, deviceModel, deviceSerial);
            }
        }

    }
}

