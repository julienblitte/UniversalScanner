using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UniversalScanner
{
    class Dahua2 : ScanEngine
    {
        protected new string multicastIP = "239.255.255.251";
        protected int port = 37810;

        protected bool _quirk = false;
        public bool quirk { set { _quirk = value; } }

        protected const UInt32 magic = 0x44484950;

        public override int color
        {
            get
            {
                return Color.DarkRed.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Dahua";
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 32, CharSet = CharSet.Ansi)]
        public struct Dahua2Header
        {
            [FieldOffset(0)] public UInt32 headerSize;
            [FieldOffset(4)] public UInt32 headerMagic;
            [FieldOffset(8)] public UInt32 reserved1;
            [FieldOffset(12)] public UInt32 reserved2;
            [FieldOffset(16)] public UInt32 packetSize1;
            [FieldOffset(20)] public UInt32 reserved3;
            [FieldOffset(24)] public UInt32 packetSize2;
            [FieldOffset(28)] public UInt32 reserved4;
        }

        public Dahua2()
        {
            listenMulticast(IPAddress.Parse(multicastIP), port);
            listenUdpInterfaces();
        }

        public override void scan()
        {
#if DEBUG
            selfTest("Dahua2.selftest");
#endif
            sendMulticast(IPAddress.Parse(multicastIP), port);

            if (_quirk)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: Using quirk mode for Dahua protocol v2");
                sendNetScan(port);
            }
        }

        private UInt32 dtohl(UInt32 value)
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

        private UInt16 dtohs(UInt16 value)
        {
            if (!BitConverter.IsLittleEndian)
            {
                value = (UInt16)((value << 8) | (value >> 8));
            }

            return value;
        }

        public override byte[] sender(IPEndPoint dest)
        {
            Dahua2Header header;
            byte[] headerArray;
            string bodyStr;
            byte[] bodyArray;
            byte[] result;
            int headerSize;

            header = new Dahua2Header {
                headerSize = dtohl((UInt32)typeof(Dahua2Header).StructLayoutAttribute.Size),
                headerMagic = NetworkUtils.ntohl(magic),
                reserved1 = 0,
                reserved2 = 0, 
                packetSize1 = 0, 
                reserved3 = 0,
                packetSize2 = 0,
                reserved4 = 0
            };

            bodyStr = "{ \"method\" : \"DHDiscover.search\", \"params\" : { \"mac\" : \"\", \"uni\" : 1 } }\r\n";
            bodyArray = Encoding.UTF8.GetBytes(bodyStr);

            headerSize = typeof(Dahua2Header).StructLayoutAttribute.Size; 

            result = new byte[headerSize + bodyArray.Length];
            header.packetSize1 = (UInt32)bodyArray.Length;
            header.packetSize2 = (UInt32)bodyArray.Length;

            headerArray = header.GetBytes();

            headerArray.CopyTo(result, 0);
            bodyArray.CopyTo(result, headerSize);

            return result;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            Dahua2Header header;
            string bodyStr;
            byte[] body;
            int headerSize, packetSize;
            string method;

            headerSize = typeof(Dahua2Header).StructLayoutAttribute.Size;

            header = data.GetStruct<Dahua2Header>();

            if (dtohl(header.headerSize) != headerSize)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: reciever(): recieved invalid frame (headerSize={0}, expected {1})!", header.headerSize, headerSize));
                return;
            }
            packetSize = data.Length - headerSize;
            if (dtohl(header.packetSize1) != packetSize)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: reciever(): recieved invalid frame (packetSize={0}, expected {1})!", dtohl(header.packetSize1), packetSize));
                return;
            }

            body = new byte[packetSize];
            for (int i = 0; i < packetSize; i++)
                body[i] = data[headerSize + i];

            bodyStr = Encoding.UTF8.GetString(body);

            method = extractJsonString("method", bodyStr);
            if (method == "client.notifyDevInfo")
            {
                string deviceModel, deviceIP, deviceSerial;

                deviceModel = extractJsonString("DeviceType", bodyStr);
                if (deviceModel == null)
                {
                    deviceModel = "Dahua";
                }

                deviceIP = extractJsonString("IPAddress", bodyStr);
                if (deviceIP == null)
                {
                    deviceIP = from.Address.ToString();
                }

                deviceSerial = extractJsonString("SerialNo", bodyStr);
                if (deviceSerial == null)
                {
                    deviceSerial = extractJsonString("mac", bodyStr);
                }
                if (deviceSerial == null)
                {
                    deviceSerial = "Dahua device";
                }

                viewer.deviceFound(name, 2, deviceIP, deviceModel, deviceSerial);
            }
        }

        private string extractJsonString(string key, string json)
        {
            Regex reg;
            Match m;

            reg = new Regex(String.Format("\"{0}\" *: *\"([^\"]*)\"", key));
            m = reg.Match(json);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }

            return null;
        }
    }
}
