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
            IPAddress ip;

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
                string deviceModel, deviceIPv4, deviceIPv6, deviceSerial;
                string IPv4Section, IPv6Section;

                deviceModel = extractJsonString("DeviceType", bodyStr);
                if (deviceModel == null)
                {
                    deviceModel = "Dahua";
                }

                IPv4Section = extractJsonSection("IPv4Address", bodyStr);
                deviceIPv4 = extractJsonString("IPAddress", IPv4Section);
                if (deviceIPv4 == null)
                {
                    deviceIPv4 = from.Address.ToString();
                }

                deviceIPv6 = null;
                IPv6Section = extractJsonSection("IPv6Address", bodyStr);
                if (IPv6Section != null)
                {
                    deviceIPv6 = extractJsonString("IPAddress", IPv6Section);
                    if (deviceIPv6 != null)
                    {
                        int sub = deviceIPv6.IndexOfAny(new char[] { '/', '\\' });
                        if (sub > 0)
                        {
                            deviceIPv6 = deviceIPv6.Substring(0, sub - 1);
                        }
                    }
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


                if (!IPAddress.TryParse(deviceIPv4, out ip))
                {
                    ip = from.Address;
                    Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua2.reciever(): Invalid ipv4 format: {0}", deviceIPv4));
                }
                viewer.deviceFound(name, 2, ip, deviceModel, deviceSerial);

                if (deviceIPv6 != null)
                {
                    if (IPAddress.TryParse(deviceIPv6, out ip))
                    {
                        viewer.deviceFound(name, 2, ip, deviceModel, deviceSerial);
                    }
                    else
                    {
                        Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua2.reciever(): Invalid ipv6 format: {0}", deviceIPv4));
                    }
                }
            }
        }

        private string extractJsonSection(string key, string json)
        {
            Regex reg;
            Match m;

            reg = new Regex(String.Format("\"{0}\" *: *({1}[^{2}]*{2})", key, "\\{", "\\}"));
            m = reg.Match(json);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }

            return null;
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
