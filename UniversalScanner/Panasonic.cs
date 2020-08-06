using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class Panasonic : ScanEngine
    {
        private const int port = 10670;
        private const int answerPort = 10669;

        enum AnswerValues
        {
            ipv4 = 0x20,
            mask = 0x21,
            gateway = 0x22,
            ipv6 = 0x40,
            fullname = 0xa7,
            shortname = 0xa8
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
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x34, CharSet = CharSet.Ansi)]
        public struct PanasonicDiscovery
        {
            [FieldOffset(0x00)] public UInt32 headerMagic;
            [FieldOffset(0x04)] public UInt32 _uint32_04;
            [FieldOffset(0x08)] public UInt32 _uint32_08;
            [FieldOffset(0x0C)] MacAddress mac;
            [FieldOffset(0x12)] public UInt32 ip;
            [FieldOffset(0x16)] public UInt32 _uint32_16;
            [FieldOffset(0x1A)] public UInt32 _uint32_1A;
            [FieldOffset(0x1E)] public UInt32 _uint32_1E;
            [FieldOffset(0x22)] public UInt32 _uint32_22;
            [FieldOffset(0x26)] public UInt32 _uint32_26;
            [FieldOffset(0x2A)] public UInt32 _uint32_2A;
            [FieldOffset(0x2E)] public UInt32 _uint32_2E;
            [FieldOffset(0x32)] public UInt16 checksum;

            public PanasonicDiscovery(PhysicalAddress macAddress, IPAddress _ip)
            {
                byte[] ipBytes;
                UInt32 ipUInt32;

                _uint32_04 = NetworkUtils.bigEndian32(0x000d0000);
                _uint32_08 = NetworkUtils.bigEndian32(0x00000000);

                headerMagic = NetworkUtils.bigEndian32(0x00010000);

                mac = macAddress.GetAddressBytes().GetStruct<MacAddress>();

                ipBytes = _ip.GetAddressBytes();
                ipUInt32 = (UInt32)((ipBytes[0] << 24) |
                    (ipBytes[1] << 16) |
                    (ipBytes[2] << 8) |
                    (ipBytes[3]));
                ip = NetworkUtils.bigEndian32(ipUInt32);

                _uint32_16 = NetworkUtils.bigEndian32(0x00012011);
                _uint32_1A = NetworkUtils.bigEndian32(0x1e11231f);
                _uint32_1E = NetworkUtils.bigEndian32(0x1e191300);
                _uint32_22 = NetworkUtils.bigEndian32(0x00020000);
                _uint32_26 = NetworkUtils.bigEndian32(0x00000000);
                _uint32_2A = NetworkUtils.bigEndian32(0x00000000);
                _uint32_2E = NetworkUtils.bigEndian32(0x0000ffff);
                checksum = NetworkUtils.bigEndian16(0x0000);
            }
        }

        public Panasonic()
        {
            listenUdpGlobal(answerPort);
            listenUdpInterfaces();
        }

        public override string name
        {
            get
            {
                return "Panasonic";
            }
        }
        public override int color
        {
            get
            {
                return Color.Black.ToArgb();
            }
        }

        Dictionary<UInt16, byte[]> parsePacket(byte[] data)
        {
            Dictionary<UInt16, byte[]> result;
            int i;
            
            result = new Dictionary<UInt16, byte[]>();

            i = 53;
            while (i < data.Length-4)
            {
                UInt16 key;
                UInt16 length;
                byte[] value;

                key = data[i];
                i++;
                key <<= 8;
                key |= data[i];
                i++;

                length = data[i];
                i++;
                length <<= 8;
                length |= data[i];
                i++;

                if (i + length >= data.Length)
                {
                    Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: Panasonic.parsePacket(): packet overflow");
                    return result;
                }

                value = new byte[length];
                Array.Copy(data, i, value, 0, length);
                result.Add(key, value);

                i += length;
            }
            return result;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            Dictionary<UInt16, byte[]> values;
            string model;
            IPAddress ip;
            byte[] macAddress;

            if (data.Length <= 52)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Panasonic.reciever(): Invalid packet size: {0}", data.Length));
                return;
            }

            macAddress = new byte[6];
            Array.Copy(data, 6, macAddress, 0, 6);

            values = parsePacket(data);

            model = null;
            if (values.ContainsKey((UInt16)AnswerValues.fullname))
            {
                model = Encoding.UTF8.GetString(values[(UInt16)AnswerValues.fullname]);
            }
            else if (values.ContainsKey((UInt16)AnswerValues.shortname))
            {
                model = Encoding.UTF8.GetString(values[(UInt16)AnswerValues.shortname]);
            }

            ip = null;
            if (values.ContainsKey((UInt16)AnswerValues.ipv4) && model != null)
            {
                ip = new IPAddress(values[(UInt16)AnswerValues.ipv4]);
            }

            if (model != null && ip != null)
            {
                viewer.deviceFound(name, 1, ip, model, String.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                    macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]));
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
            PanasonicDiscovery discover;

            discover = new PanasonicDiscovery(new PhysicalAddress(new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}), dest.Address);

            return discover.GetBytes();
        }
    }
}
