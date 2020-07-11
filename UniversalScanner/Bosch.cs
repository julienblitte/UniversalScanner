using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

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

        [StructLayout(LayoutKind.Explicit, Size = 6, CharSet = CharSet.Ansi)]
        public struct MacAddress
        {
            [FieldOffset(0)] public byte byte00;
            [FieldOffset(1)] public byte byte01;
            [FieldOffset(2)] public byte byte02;
            [FieldOffset(3)] public byte byte03;
            [FieldOffset(4)] public byte byte04;
            [FieldOffset(5)] public byte byte05;
        };

        [StructLayout(LayoutKind.Explicit, Size = 32, CharSet = CharSet.Ansi)]
        public struct BoschBinaryAnswer
        {
            [FieldOffset(0)] public UInt32 magic;
            [FieldOffset(4)] public UInt32 transactionID;
            [FieldOffset(8)] public MacAddress mac;
            [FieldOffset(14)] public byte _0D_value;
            [FieldOffset(15)] public byte _0E_value;
            [FieldOffset(16)] public UInt32 ipv4;
            [FieldOffset(20)] public UInt32 mask;
            [FieldOffset(24)] public UInt32 gateway;
            [FieldOffset(28)] public byte _1C_value;
            [FieldOffset(29)] public byte _1D_value;
            [FieldOffset(20)] public byte _1E_value;
            [FieldOffset(31)] public byte _1F_value;
        };

        [StructLayout(LayoutKind.Explicit, Size = 12, CharSet = CharSet.Ansi)]
        public struct BoschRequest
        {
            [FieldOffset(0)] public UInt32 magic;
            [FieldOffset(4)] public UInt32 transactionID;
            [FieldOffset(8)] public UInt32 requestMagic;
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
                   Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: Bosch.reciever(): Packet with wrong header.");
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
                    Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Bosch.reciever(): Invalid ipv4 format: {0}", deviceIPv4Str));
                    ip = from.Address;
                }
                viewer.deviceFound(name, 2, ip, deviceModel, deviceSerial);

                if (IPAddress.TryParse(deviceIPv6Str, out ip))
                {
                    viewer.deviceFound(name, 2, ip, deviceModel, deviceSerial);
                }
                else
                {
                    Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Bosch.reciever(): Invalid ipv6 format: {0}", deviceIPv6Str));
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
