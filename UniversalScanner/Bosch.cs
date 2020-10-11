using System;
using System.Drawing;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using JulienBlitte;

namespace UniversalScanner
{
    class Bosch : ScanEngine
    {
        private const int requestPort = 1757;
        private const int answerPort = 1758;

        private const UInt32 requestMagic = 0xff0006de;
        private const UInt32 answerMagic = 0x9939a427;

        public override string name
        {
            get
            {
                return "Bosch";
            }
        }
        public override int color
        {
            get
            {
                return Color.Red.ToArgb();
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x06, CharSet = CharSet.Ansi)]
        public struct MacAddress
        {
            [FieldOffset(0x00)] public byte byte00;
            [FieldOffset(0x01)] public byte byte01;
            [FieldOffset(0x02)] public byte byte02;
            [FieldOffset(0x03)] public byte byte03;
            [FieldOffset(0x04)] public byte byte04;
            [FieldOffset(0x05)] public byte byte05;
        };

        [StructLayout(LayoutKind.Explicit, Size = 0x20, CharSet = CharSet.Ansi)]
        public struct BoschBinaryAnswer
        {
            [FieldOffset(0x00)] public UInt32 magic;
            [FieldOffset(0x04)] public UInt32 transactionID;
            [FieldOffset(0x08)] public MacAddress mac;
            [FieldOffset(0x0E)] public byte _byte_0E;
            [FieldOffset(0x0F)] public byte _byte_0F;
            [FieldOffset(0x10)] public UInt32 ipv4;
            [FieldOffset(0x14)] public UInt32 mask;
            [FieldOffset(0x18)] public UInt32 gateway;
            [FieldOffset(0x1C)] public byte _byte_1C;
            [FieldOffset(0x1D)] public byte _byte_1D;
            [FieldOffset(0x1E)] public byte _byte_1E;
            [FieldOffset(0x1F)] public byte _byte_1F;
        };

        [StructLayout(LayoutKind.Explicit, Size = 0x0C, CharSet = CharSet.Ansi)]
        public struct BoschRequest
        {
            [FieldOffset(0x00)] public UInt32 magic;
            [FieldOffset(0x04)] public UInt32 transactionID;
            [FieldOffset(0x08)] public UInt32 requestMagic;
        };

        public Bosch()
        {
            listenUdpGlobal(answerPort);
            listenUdpInterfaces();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string deviceModel, deviceSerial;

            // xml is much bigger
            if (data.Length == typeof(BoschBinaryAnswer).StructLayoutAttribute.Size)
            {
                BoschBinaryAnswer binary;
                UInt32 ip;

                binary = data.GetStruct<BoschBinaryAnswer>();

                if (NetworkUtils.bigEndian32(binary.magic) != answerMagic)
                {
                   Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, "Warning: Bosch.reciever(): Packet with wrong header.");
                    return;
                }

                ip = NetworkUtils.littleEndian32(binary.ipv4);

                deviceSerial = String.Format("{0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}", binary.mac.byte00, binary.mac.byte01, binary.mac.byte02,
                                            binary.mac.byte03, binary.mac.byte04, binary.mac.byte05);

                deviceModel = name;

                viewer.deviceFound(name, 1, new IPAddress(ip), deviceModel, deviceSerial);
            }
            else
            {
                string xml;
                string deviceIPv4Str, deviceIPv6Str;
                Regex type, ipv4, ipv6, mac, serial;
                Match m;
                IPAddress ip;

                xml = Encoding.UTF8.GetString(data);
                type = new Regex("<friendlyName>([^<]*)</friendlyName>");
                ipv4 = new Regex("<unitIPAddress>([^<]*)</unitIPAddress>");
                ipv6 = new Regex("<unitIPv6Address>([^<]*)</unitIPv6Address>");
                mac = new Regex("<physAddress>([^<]*)</physAddress>");
                serial = new Regex("<serialNumber>([^<]*)</serialNumber>");

                deviceIPv4Str = "";
                m = ipv4.Match(xml);
                if (m.Success)
                {
                    deviceIPv4Str = m.Groups[1].Value;
                }

                deviceIPv6Str = "";
                m = ipv6.Match(xml);
                if (m.Success)
                {
                    deviceIPv6Str = m.Groups[1].Value;
                }

                deviceModel = "";
                m = type.Match(xml);
                if (m.Success)
                {
                    deviceModel = m.Groups[1].Value;
                }

                deviceSerial = "";
                m = serial.Match(xml);
                if (m.Success)
                {
                    deviceSerial = m.Groups[1].Value;
                }
                else
                {
                    m = mac.Match(xml);
                    if (m.Success)
                    {
                        deviceSerial = m.Groups[1].Value;
                    }
                }

                if (!IPAddress.TryParse(deviceIPv4Str, out ip))
                {
                    Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Bosch.reciever(): Invalid ipv4 format: {0}", deviceIPv4Str));
                    ip = from.Address;
                }
                viewer.deviceFound(name, 2, ip, deviceModel, deviceSerial);

                if (IPAddress.TryParse(deviceIPv6Str, out ip))
                {
                    viewer.deviceFound(name, 2, ip, deviceModel, deviceSerial);
                }
                else
                {
                    Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Bosch.reciever(): Invalid ipv6 format: {0}", deviceIPv6Str));
                }
            }
        }

        public override void scan()
        {
#if DEBUG
            selfTest("Bosch.bin.selftest");
            selfTest("Bosch.xml.selftest");
#endif
            sendBroadcast(requestPort);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            BoschRequest request;
            byte[] result;
            DateTime date;

            date = DateTime.UtcNow;

            request = new BoschRequest();
            request.magic = NetworkUtils.bigEndian32(answerMagic);
            request.transactionID = NetworkUtils.bigEndian32((UInt32)
                ((date.Hour << 24) | (date.Minute << 16) | 
                (date.Second << 8) | (date.Millisecond / 10)
                ));
            request.requestMagic = NetworkUtils.bigEndian32(requestMagic);

            result = request.GetBytes();

            return result;
        }
    }
}
