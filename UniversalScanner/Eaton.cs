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
    class Eaton : ScanEngine
    {
        private const int port = 4679;
        private readonly string request = "<SCAN_REQUEST/>";

        public override int color
        {
            get
            {
                return Color.Blue.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Eaton";
            }
        }
        public Eaton()
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
            return Encoding.UTF8.GetBytes(request);
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string xml;
            string deviceModel, deviceSerial;

            xml = Encoding.UTF8.GetString(data);

            deviceModel = extractObjectEntry("System.Description", xml);
            if (deviceModel == null)
            {
                deviceModel = extractObjectEntry("UPS.PowerSummary.iProduct", xml);
            }

            if (deviceModel == null)
            {
                return;
            }

            deviceSerial = extractObjectEntry("UPS.PowerSummary.iSerialNumber", xml);
            if (deviceSerial == null)
            {
                deviceSerial = "Unknown";
            }

            viewer.deviceFound(name, 1, from.Address, deviceModel, deviceSerial);
        }

        private string extractObjectEntry(string name, string xml)
        {
            Regex reg;
            Match m;

            reg = new Regex(String.Format("<OBJECT +name *= *\"{0}\">([^<]*)</OBJECT>", name));
            m = reg.Match(xml);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }

            return null;
        }

    }
}

