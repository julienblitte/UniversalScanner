using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class Ubiquiti : ScanEngine
    {
        protected new readonly string multicastIP = "233.89.188.1";
        protected const int port = 10001;

        protected readonly UInt32 version = 1;

        public override int color
        {
            get
            {
                return Color.DarkCyan.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Ubiquiti";
            }
        }

        public Ubiquiti()
        {
            listenMulticast(IPAddress.Parse(multicastIP), port);
            listenUdpInterfaces();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            viewer.deviceFound(name, 1, from.Address.ToString(), "unkown", "unkown");
        }

        public override void scan()
        {
#if DEBUG
            selfTest();
#endif
            sendMulticast(IPAddress.Parse(multicastIP), port);
            sendBroadcast(port);
        }

        private UInt32 utohl(UInt32 value)
        {
            if (!BitConverter.IsLittleEndian)
            {
                value = value << 24
                    | ((value << 8) & 0x00ff0000)
                    | ((value >> 8) & 0x0000ff00)
                    | (value >> 24);
            }

            return value;
        }

        public override byte[] sender(IPEndPoint dest)
        {
            UInt32 payload;
            payload = utohl(version);

            return payload.GetBytes();
        }
    }
}
