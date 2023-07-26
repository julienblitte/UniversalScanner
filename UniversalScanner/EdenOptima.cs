using System;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

/*
 * @description: UniversalScanner discovery protocol
 */

namespace UniversalScanner
{
    class EdenOptima : ScanEngine
    {
        private const int port = 8088;

        private readonly string requestMagic = "DETECT BOX";
        private readonly string answerMagic = "BOX";

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
                return "Eden";
            }
        }
        public EdenOptima()
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
            string text;
            string deviceIP, deviceSerial;
            string[] fields;
            IPAddress ip;

            text = Encoding.UTF8.GetString(data);
            fields = text.Split('|');

            if (fields.Length >= 1)
            {
                if (fields[0] != answerMagic)
                {
                    Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Eden.reciever(): Invalid signature field: {0}", fields[0]));
                    return;
                }
            }

            deviceSerial = extractXMLString("serialNumber",  fields[1]);

            deviceIP = extractXMLString("adresseIP",  fields[1]);


            if (IPAddress.TryParse(deviceIP, out ip))
            {
                viewer.deviceFound(name, 1, ip, "Optima box", deviceSerial);
            }
            else
            {
                viewer.deviceFound(name, 1, from.Address, "Optima box", deviceSerial);
            }
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

