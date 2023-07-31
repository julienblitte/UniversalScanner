using System;
using System.Drawing;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using JulienBlitte;

namespace UniversalScanner
{
    class Dahua2 : ScanEngine
    {
        private static readonly string multicastIP = "239.255.255.251";
        private const int port = 37810;

        private const UInt32 magic = 0x44484950;   // 'DHIP'

        public override int color
        {
            get
            {
                return Color.DarkRed.ToArgb();
            }
        }

        public override UInt16[] getUsedPort()
        {
            return new UInt16[] { port };
        }
        public override string name
        {
            get
            {
                return "Dahua";
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x20, CharSet = CharSet.Ansi)]
        public struct Dahua2Header
        {
            [FieldOffset(0x00)] public UInt32 headerSize;
            [FieldOffset(0x04)] public UInt32 headerMagic;
            [FieldOffset(0x08)] public UInt32 _reserved_08;
            [FieldOffset(0x0C)] public UInt32 _reserved_0C;
            [FieldOffset(0x10)] public UInt32 packetSize1;
            [FieldOffset(0x14)] public UInt32 _reserved_14;
            [FieldOffset(0x18)] public UInt32 packetSize2;
            [FieldOffset(0x1C)] public UInt32 _reserved_1C;
        }

        public Dahua2()
        {

        }
        public override void listen()
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
            sendBroadcast(port);
            if (Config.getInstance().DahuaNetScan)
            {
                sendNetScan(port);
            }
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
                headerSize = NetworkUtils.littleEndian32((UInt32)typeof(Dahua2Header).StructLayoutAttribute.Size),
                headerMagic = NetworkUtils.bigEndian32(magic),
                _reserved_08 = 0,
                _reserved_0C = 0, 
                packetSize1 = 0, 
                _reserved_14 = 0,
                packetSize2 = 0,
                _reserved_1C = 0
            };

            bodyStr = "{\"method\":\"DHDiscover.search\",\"params\":{\"mac\":\"\",\"uni\":0}}\n";
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

            if (NetworkUtils.littleEndian32(header.headerSize) != headerSize)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua2.reciever(): recieved invalid frame (headerSize={0}, expected {1})!", header.headerSize, headerSize));
                return;
            }
            packetSize = data.Length - headerSize;
            if (NetworkUtils.littleEndian32(header.packetSize1) != packetSize)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua2.reciever(): recieved invalid frame (packetSize={0}, expected {1})!", NetworkUtils.littleEndian32(header.packetSize1), packetSize));
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
                    Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua2.reciever(): Invalid ipv4 format: {0}", deviceIPv4));
                }

                if (ip.Equals(IPAddress.Parse("0.0.0.0")))
                {
                    ip = from.Address;
                    Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua2.reciever(): Recieved ipv4 is null (from: {0})", from.Address.ToString()));
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
                        Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua2.reciever(): Invalid ipv6 format: {0}", deviceIPv6));
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
