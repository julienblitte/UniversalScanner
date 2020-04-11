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
            sendMulticast(IPAddress.Parse(multicastIP), port);

            if (_quirk)
            {
                traceWriteLine(debugLevel.Warn, "Warning: Using quirk mode for Dahua protocol v2");
                sendNetScan(port);
            }
        }

        public override byte[] sender(IPEndPoint dest)
        {
            Dahua2Header header;
            string bodyStr;
            byte[] body;
            byte[] result;
            int headerSize;

            header = new Dahua2Header {
                headerSize = 0x20,
                headerMagic = ntohl(magic),
                reserved1 = 0,
                reserved2 = 0, 
                packetSize1 = 0, 
                reserved3 = 0,
                packetSize2 = 0,
                reserved4 = 0
            };

            bodyStr = "{ \"method\" : \"DHDiscover.search\", \"params\" : { \"mac\" : \"\", \"uni\" : 1 } }\r\n";
            body = Encoding.UTF8.GetBytes(bodyStr);

            headerSize = Marshal.SizeOf(header);

            result = new byte[headerSize + body.Length];
            header.packetSize1 = (UInt32)body.Length;
            header.packetSize2 = (UInt32)body.Length;

            IntPtr ptr = Marshal.AllocHGlobal(headerSize);
            try
            {
                Marshal.StructureToPtr<Dahua2Header>(header, ptr, false);
                Marshal.Copy(ptr, result, 0, headerSize);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            body.CopyTo(result, headerSize);

            return result;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            Dahua2Header header;
            string bodyStr;
            byte[] body;
            int headerSize, packetSize;
            string method;

            headerSize = Marshal.SizeOf(typeof(Dahua2Header));

            IntPtr ptr = Marshal.AllocHGlobal(headerSize);
            try
            {
                Marshal.Copy(data, 0, ptr, headerSize);
                header = Marshal.PtrToStructure<Dahua2Header>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            if (header.headerSize != headerSize)
            {
                traceWriteLine(debugLevel.Warn, String.Format("Warning: reciever(): recieved invalid frame (headerSize={0}, expected {1})!", header.headerSize, headerSize));
                return;
            }
            packetSize = data.Length - headerSize;
            if (header.packetSize1 != header.packetSize2 || header.packetSize1 != packetSize)
            {
                traceWriteLine(debugLevel.Warn, String.Format("Warning: reciever(): recieved invalid frame (packetSize={0} and {1}, expected {2})!", header.packetSize1, header.packetSize2, packetSize));
                return;
            }

            body = new byte[packetSize];
            for (int i = 0; i < packetSize; i++)
                body[i] = data[headerSize + i];

            bodyStr = Encoding.UTF8.GetString(body);

            method = extractJsonString("method", bodyStr);
            if (method == "client.notifyDevInfo")
            {
                string deviceType, deviceIP, deviceDesc;

                deviceType = extractJsonString("DeviceType", bodyStr);
                if (deviceType == null)
                {
                    deviceType = "Dahua";
                }

                deviceIP = extractJsonString("IPAddress", bodyStr);
                if (deviceIP == null)
                {
                    deviceIP = from.Address.ToString();
                }

                deviceDesc = extractJsonString("SerialNo", bodyStr);
                if (deviceDesc == null)
                {
                    deviceDesc = extractJsonString("mac", bodyStr);
                }
                if (deviceDesc == null)
                {
                    deviceDesc = "Dahua device";
                }

                viewer.deviceFound(name, 2, deviceIP, deviceType, deviceDesc);
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
