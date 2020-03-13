using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class Hikvision : ScanEngine
    {
        protected new string multicastIP = "239.255.255.250";
        protected int port = 37020;

        public override int color
        {
            get
            {
                return Color.Red.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Hikvision";
            }
        }

        public Hikvision()
        {
            listenMulticast(IPAddress.Parse(multicastIP), port);
            listenUdpInterfaces();
        }
        
        public static string getAssemblyUUID()
        {
            var assembly = typeof(Program).Assembly;
            var attribute = (GuidAttribute)assembly.GetCustomAttributes(typeof(GuidAttribute), true)[0];
            return attribute.Value;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string xml;
            string deviceIP, deviceType, deviceSN;

            xml = Encoding.UTF8.GetString(data);

            if (!xml.Contains("<ProbeMatch>"))
            {
                return;
            }

            deviceType = extractXMLString("DeviceDescription", xml);
            deviceIP = extractXMLString("IPv4Address", xml);
            if (deviceIP == null)
            {
                deviceIP = from.Address.ToString();
            }
            deviceSN = extractXMLString("DeviceSN", xml);

            viewer.deviceFound(name, deviceIP, deviceType, deviceSN);
        }

        public override void scan()
        {
            sendMulticast(IPAddress.Parse(multicastIP), port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return Encoding.UTF8.GetBytes(String.Format("<?xml version=\"1.0\" encoding=\"utf-8\"?><Probe><Uuid>{0}</Uuid><Types>inquiry</Types></Probe>",
                getAssemblyUUID()));
        }

        private string extractXMLString(string tag, string xml)
        {
            Regex reg;
            Match m;

            reg = new Regex(String.Format("<{0}>([^<]*)</{0}>", tag));
            m = reg.Match(xml);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }

            return null;
        }
    }
}
