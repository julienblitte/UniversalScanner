using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class Sony : ScanEngine
    {
        protected const int port = 2380;
        protected const byte marker_start = 0x02;
        protected const byte marker_end = 0x03;
        protected const byte marker_EOS = 0xff;

        public override string name
        {
            get
            {
                return "Sony";
            }
        }
        public override int color
        {
            get
            {
                return Color.Black.ToArgb();
            }
        }

        public Sony()
        {
            listenUdpInterfaces();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string[] answerStringList;
            string model, serial, mac, ipv4;

            answerStringList = readPacket(data);

            model = null;
            serial = null;
            mac = null;
            ipv4 = null;

            foreach (var line in answerStringList)
            {
                var v = line.Split(':');
                if (v.Length == 2)
                {
                    string variable = v[0].ToLower().Trim();
                    string value = v[1];
                    if (variable == "model")
                    {
                        model = value;
                    }
                    if (variable == "serial")
                    {
                        serial = value;
                    }
                    if (variable == "mac")
                    {
                        mac = value;
                    }
                    if (variable == "ipadr")
                    {
                        ipv4 = value;
                    }
                }
            }

            if (ipv4 != null && model != null)
            {
                IPAddress ip;
                if (serial == null)
                {
                    serial = mac;
                }
                if (serial == null)
                {
                    serial = "unkonwn";
                }

                if (!IPAddress.TryParse(ipv4, out ip))
                {
                    ip = from.Address;
                    Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Sony.reciever(): Invalid ipv4 format: {0}", ipv4));
                }
                viewer.deviceFound(name, 1, ip, model, serial);
            }
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
            return writePacket(new string[] { "ENQ:allinfo" });
        }

        private byte[] writePacket(string[] lines)
        {
            List<byte> result;

            result = new List<byte>();
            result.Add(marker_start);
            foreach(var l in lines)
            {
                var bytesLine = Encoding.UTF8.GetBytes(l);
                foreach(var b in bytesLine)
                {
                    result.Add(b);
                }
                result.Add(marker_EOS);
            }
            result.Add(marker_end);

            return result.ToArray();
        }

        private string[] readPacket(byte[] binary)
        {
            List<string> result;
            int lastMarker;

            result = new List<string>();
            if (binary.Length < 2)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: Sony.readPacket(): Invalid packet size!");
                return result.ToArray();
            }
            if (binary[0] != marker_start)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: Sony.readPacket(): Invalid packet start marker!");
                return result.ToArray();
            }
            if (binary[binary.Length-1] != marker_end)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: Sony.readPacket(): Invalid packet end marker!");
                return result.ToArray();
            }
            lastMarker = 0; 
            for (int i = 1; i < binary.Length-1; i++)
            {
                if (binary[i] == marker_EOS)
                {
                    result.Add(Encoding.UTF8.GetString(binary, lastMarker+1, i-lastMarker-1));
                    lastMarker = i;
                }
            }
            return result.ToArray();
        }
    }
}
