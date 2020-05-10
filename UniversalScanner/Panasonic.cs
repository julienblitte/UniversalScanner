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

        [StructLayout(LayoutKind.Explicit, Size = 6, CharSet = CharSet.Ansi)]
        public struct MacAddress
        {
            [FieldOffset(0)] public byte byte0;
            [FieldOffset(1)] public byte byte1;
            [FieldOffset(2)] public byte byte2;
            [FieldOffset(3)] public byte byte3;
            [FieldOffset(4)] public byte byte4;
            [FieldOffset(5)] public byte byte5;
        }

        [StructLayout(LayoutKind.Explicit, Size = 52, CharSet = CharSet.Ansi)]
        public struct PanasonicDiscovery
        {
            [FieldOffset(0)] public UInt32 headerMagic;
            [FieldOffset(4)] public UInt32 payload1;
            [FieldOffset(8)] public UInt32 payload2;
            [FieldOffset(12)] MacAddress mac;
            [FieldOffset(18)] public UInt32 ip;
            [FieldOffset(22)] public UInt32 payload3;
            [FieldOffset(26)] public UInt32 payload4;
            [FieldOffset(30)] public UInt32 payload5;
            [FieldOffset(34)] public UInt32 payload6;
            [FieldOffset(38)] public UInt32 payload7;
            [FieldOffset(42)] public UInt32 payload8;
            [FieldOffset(46)] public UInt32 payload9;
            [FieldOffset(50)] public UInt16 checksum;

            public PanasonicDiscovery(PhysicalAddress macAddress, IPAddress _ip)
            {
                byte[] ipBytes;
                UInt32 ipUInt32;

                payload1 = 0x000d0000;
                payload2 = 0x00000000;

                headerMagic = NetworkUtils.htonl(0x00010000);

                mac = macAddress.GetAddressBytes().GetStruct<MacAddress>();

                ipBytes = _ip.GetAddressBytes();
                ipUInt32 = (UInt32)((ipBytes[0] << 24) |
                    (ipBytes[1] << 16) |
                    (ipBytes[2] << 8) |
                    (ipBytes[3]));
                ip = NetworkUtils.htonl(ipUInt32);

                payload3 = NetworkUtils.htonl(0x00012011);
                payload4 = NetworkUtils.htonl(0x1e11231f);
                payload5 = NetworkUtils.htonl(0x1e191300);
                payload6 = NetworkUtils.htonl(0x00020000);
                payload7 = NetworkUtils.htonl(0x00000000);
                payload8 = NetworkUtils.htonl(0x00000000);
                payload9 = NetworkUtils.htonl(0x0000ffff);
                checksum = NetworkUtils.htons(0x0000);
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
