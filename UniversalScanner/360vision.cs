using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class _360vision : ScanEngine
    {
        protected int port = 3600;

        private string request = "DISCOVER\n";

        public override string name
        {
            get
            {
                return "360vision";
            }
        }
        public override int color
        {
            get
            {
                return Color.Purple.ToArgb();
            }
        }

        public _360vision()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
        }

        private string[] readStrings(byte[] data)
        {
            StringBuilder sb;
            List<string> result;

            result = new List<string>();
            sb = new StringBuilder();
            for(int i=0; i < data.Length; i++)
            {
                if (data[i] == '\n' || data[i] == '\0')
                {
                    if (sb.Length > 0)
                    {
                        result.Add(sb.ToString());
                        sb = new StringBuilder();
                    }
                    continue;
                }
                sb.Append((char)data[i]);
            }
            if (sb.Length > 0)
            {
                result.Add(sb.ToString());
            }
            return result.ToArray();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string[] reply;
            string type;
            string serial;

            reply = readStrings(data);
            if (reply.Length == 0)
            {
                return;
            }
            if (reply[0] == "DISCOVER")
            {
                return;
            }

            type = "Unknown";
            if (reply.Length >= 2)
            {
                type = reply[1];
            }

            serial = "Unknown";
            if (reply.Length >= 3)
            {
                serial = reply[2];
            }

            viewer.deviceFound(name, 1, from.Address, type, serial);
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
    }
}
