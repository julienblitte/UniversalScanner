using System;
using System.Drawing;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using JulienBlitte;

namespace UniversalScanner
{
    class Hanwha : ScanEngine
    {
        private const int answerPort = 7711;
        private const int requestPort = 7701;

        public override int color
        {
            get
            {
                return Color.DarkOrange.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Hanwha";
            }
        }

        private const byte packet_type_request = 0x01;
        private const byte packet_type_reply = 0x0b;

        [StructLayout(LayoutKind.Explicit, Size = 0x0A, CharSet = CharSet.Ansi)]
        public struct String10bytes
        {
            [FieldOffset(0x00)] public byte byte00;
            [FieldOffset(0x01)] public byte byte01;
            [FieldOffset(0x02)] public byte byte02;
            [FieldOffset(0x03)] public byte byte03;
            [FieldOffset(0x04)] public byte byte04;
            [FieldOffset(0x05)] public byte byte05;
            [FieldOffset(0x06)] public byte byte06;
            [FieldOffset(0x07)] public byte byte07;
            [FieldOffset(0x08)] public byte byte08;
            [FieldOffset(0x09)] public byte byte09;
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x10, CharSet = CharSet.Ansi)]
        public struct String16bytes
        {
            [FieldOffset(0x00)] public byte byte00;
            [FieldOffset(0x01)] public byte byte01;
            [FieldOffset(0x02)] public byte byte02;
            [FieldOffset(0x03)] public byte byte03;
            [FieldOffset(0x04)] public byte byte04;
            [FieldOffset(0x05)] public byte byte05;
            [FieldOffset(0x06)] public byte byte06;
            [FieldOffset(0x07)] public byte byte07;
            [FieldOffset(0x08)] public byte byte08;
            [FieldOffset(0x09)] public byte byte09;
            [FieldOffset(0x0A)] public byte byte0A;
            [FieldOffset(0x0B)] public byte byte0B;
            [FieldOffset(0x0C)] public byte byte0C;
            [FieldOffset(0x0D)] public byte byte0D;
            [FieldOffset(0x0E)] public byte byte0E;
            [FieldOffset(0x0F)] public byte byte0F;
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x12, CharSet = CharSet.Ansi)]
        public struct String18bytes
        {
            [FieldOffset(0x00)] public byte byte00;
            [FieldOffset(0x01)] public byte byte01;
            [FieldOffset(0x02)] public byte byte02;
            [FieldOffset(0x03)] public byte byte03;
            [FieldOffset(0x04)] public byte byte04;
            [FieldOffset(0x05)] public byte byte05;
            [FieldOffset(0x06)] public byte byte06;
            [FieldOffset(0x07)] public byte byte07;
            [FieldOffset(0x08)] public byte byte08;
            [FieldOffset(0x09)] public byte byte09;
            [FieldOffset(0x0A)] public byte byte0A;
            [FieldOffset(0x0B)] public byte byte0B;
            [FieldOffset(0x0C)] public byte byte0C;
            [FieldOffset(0x0D)] public byte byte0D;
            [FieldOffset(0x0E)] public byte byte0E;
            [FieldOffset(0x0F)] public byte byte0F;
            [FieldOffset(0x10)] public byte byte10;
            [FieldOffset(0x11)] public byte byte11;
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x27, CharSet = CharSet.Ansi)]
        public struct String39bytes
        {
            [FieldOffset(0x00)] public byte byte00;
            [FieldOffset(0x01)] public byte byte01;
            [FieldOffset(0x02)] public byte byte02;
            [FieldOffset(0x03)] public byte byte03;
            [FieldOffset(0x04)] public byte byte04;
            [FieldOffset(0x05)] public byte byte05;
            [FieldOffset(0x06)] public byte byte06;
            [FieldOffset(0x07)] public byte byte07;
            [FieldOffset(0x08)] public byte byte08;
            [FieldOffset(0x09)] public byte byte09;
            [FieldOffset(0x0A)] public byte byte0A;
            [FieldOffset(0x0B)] public byte byte0B;
            [FieldOffset(0x0C)] public byte byte0C;
            [FieldOffset(0x0D)] public byte byte0D;
            [FieldOffset(0x0E)] public byte byte0E;
            [FieldOffset(0x0F)] public byte byte0F;
            [FieldOffset(0x10)] public byte byte10;
            [FieldOffset(0x11)] public byte byte11;
            [FieldOffset(0x12)] public byte byte12;
            [FieldOffset(0x13)] public byte byte13;
            [FieldOffset(0x14)] public byte byte14;
            [FieldOffset(0x15)] public byte byte15;
            [FieldOffset(0x16)] public byte byte16;
            [FieldOffset(0x17)] public byte byte17;
            [FieldOffset(0x18)] public byte byte18;
            [FieldOffset(0x19)] public byte byte19;
            [FieldOffset(0x1A)] public byte byte1A;
            [FieldOffset(0x1B)] public byte byte1B;
            [FieldOffset(0x1C)] public byte byte1C;
            [FieldOffset(0x1D)] public byte byte1D;
            [FieldOffset(0x1E)] public byte byte1E;
            [FieldOffset(0x1F)] public byte byte1F;
            [FieldOffset(0x20)] public byte byte20;
            [FieldOffset(0x21)] public byte byte21;
            [FieldOffset(0x22)] public byte byte22;
            [FieldOffset(0x23)] public byte byte23;
            [FieldOffset(0x24)] public byte byte24;
            [FieldOffset(0x25)] public byte byte25;
            [FieldOffset(0x26)] public byte byte26;
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x106, CharSet = CharSet.Ansi)]
        public struct HanwhaHeader
        {
            [FieldOffset(0x00)] public byte packet_type;   // 0x01 for request, 0x0b for answer
            [FieldOffset(0x01)] public byte _byte_01;
            [FieldOffset(0x02)] public byte _byte_02;
            [FieldOffset(0x03)] public byte _byte_03;
            [FieldOffset(0x04)] public byte _byte_04;
            [FieldOffset(0x05)] public byte _byte_05;
            [FieldOffset(0x06)] public byte _byte_06;
            [FieldOffset(0x07)] public byte _byte_07;
            [FieldOffset(0x08)] public byte _byte_08;
            [FieldOffset(0x09)] public byte _byte_09;
            [FieldOffset(0x0A)] public byte _byte_0A;
            [FieldOffset(0x0B)] public byte _byte_0B;
            [FieldOffset(0x0C)] public byte _byte_0C;
            [FieldOffset(0x0D)] public byte _byte_0D;
            [FieldOffset(0x0E)] public byte _byte_0E;
            [FieldOffset(0x0F)] public byte _byte_0F;
            [FieldOffset(0x10)] public byte _byte_10;
            [FieldOffset(0x11)] public byte _byte_11;
            [FieldOffset(0x12)] public byte _byte_12;
            [FieldOffset(0x13)] public String18bytes mac_address;
            [FieldOffset(0x25)] public String16bytes ip_address;
            [FieldOffset(0x35)] public String16bytes ip_mask;
            [FieldOffset(0x45)] public String16bytes ip_gw;
            [FieldOffset(0x55)] public byte _byte_55;
            [FieldOffset(0x56)] public byte _byte_56;
            [FieldOffset(0x57)] public byte _byte_57;
            [FieldOffset(0x58)] public byte _byte_58;
            [FieldOffset(0x59)] public byte _byte_59;
            [FieldOffset(0x5A)] public byte _byte_5A;
            [FieldOffset(0x5B)] public byte _byte_5B;
            [FieldOffset(0x5C)] public byte _byte_5C;
            [FieldOffset(0x5D)] public byte _byte_5D;
            [FieldOffset(0x5E)] public byte _byte_5E;
            [FieldOffset(0x5F)] public byte _byte_5F;
            [FieldOffset(0x60)] public byte _byte_60;
            [FieldOffset(0x61)] public byte _byte_61;
            [FieldOffset(0x62)] public byte _byte_62;
	        [FieldOffset(0x63)] public byte _byte_63;
            [FieldOffset(0x64)] public byte _byte_64;
            [FieldOffset(0x65)] public byte _byte_65;
            [FieldOffset(0x66)] public byte _byte_66;
            [FieldOffset(0x67)] public byte _byte_67;
            [FieldOffset(0x68)] public byte _byte_68;
            [FieldOffset(0x69)] public byte _byte_69;
            [FieldOffset(0x6A)] public byte _byte_6A;
            [FieldOffset(0x6B)] public byte _byte_6B;
            [FieldOffset(0x6C)] public byte _byte_6C;
            [FieldOffset(0x6D)] public String10bytes device_type;
            [FieldOffset(0x77)] public byte _byte_77;
            [FieldOffset(0x78)] public byte _byte_78;
            [FieldOffset(0x79)] public byte _byte_79;
            [FieldOffset(0x7A)] public byte _byte_7A;
            [FieldOffset(0x7B)] public byte _byte_7B;
            [FieldOffset(0x7C)] public byte _byte_7C;
            [FieldOffset(0x7D)] public byte _byte_7D;
            [FieldOffset(0x7E)] public byte _byte_7E;
            [FieldOffset(0x7F)] public byte _byte_7F;
            [FieldOffset(0x80)] public byte _byte_80;
            [FieldOffset(0x81)] public byte _byte_81;
            [FieldOffset(0x82)] public byte _byte_82;
            [FieldOffset(0x83)] public byte _byte_83;
            [FieldOffset(0x84)] public byte _byte_84;
            [FieldOffset(0x85)] public String39bytes url;
            [FieldOffset(0xAC)] public byte _AC_value;
            [FieldOffset(0xAD)] public byte _AD_value;
            [FieldOffset(0xAE)] public UInt32 _reserved_AE;
            [FieldOffset(0xB2)] public UInt32 _reserved_B2;
            [FieldOffset(0xB6)] public UInt32 _reserved_B6;
            [FieldOffset(0xBA)] public UInt32 _reserved_BA;
            [FieldOffset(0xBE)] public UInt32 _reserved_BE;
            [FieldOffset(0xC2)] public UInt32 _reserved_C2;
            [FieldOffset(0xC6)] public UInt32 _reserved_C6;
            [FieldOffset(0xCA)] public UInt32 _reserved_CA;
            [FieldOffset(0xCE)] public UInt32 _reserved_CE;
            [FieldOffset(0xD2)] public UInt32 _reserved_D2;
            [FieldOffset(0xD6)] public UInt32 _reserved_D6;
            [FieldOffset(0xDA)] public UInt32 _reserved_DA;
            [FieldOffset(0xDE)] public UInt32 _reserved_DE;
            [FieldOffset(0xE2)] public UInt32 _reserved_E2;
            [FieldOffset(0xE6)] public UInt32 _reserved_E6;
            [FieldOffset(0xEA)] public UInt32 _reserved_EA;
            [FieldOffset(0xEE)] public UInt32 _reserved_EE;
            [FieldOffset(0xF2)] public UInt32 _reserved_F2;
            [FieldOffset(0xF6)] public UInt32 _reserved_F6;
            [FieldOffset(0xFA)] public UInt32 _reserved_FA;
            [FieldOffset(0xFE)] public UInt32 _reserved_FE;
            [FieldOffset(0x102)] public UInt32 _reserved_102;
        }

        public Hanwha()
        {
            listenUdpGlobal(answerPort);
            listenUdpInterfaces();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            HanwhaHeader header;
            string deviceIP, deviceType, deviceSN;
            IPAddress ip;

            header = data.GetStruct<HanwhaHeader>();

            deviceIP = Encoding.UTF8.GetString(header.ip_address);
            deviceType = Encoding.UTF8.GetString(header.device_type);
            deviceSN = Encoding.UTF8.GetString(header.mac_address);
            
            if (!IPAddress.TryParse(deviceIP, out ip))
            {
                ip = from.Address;
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Hawha.reciever(): Invalid ipv4 format: {0}", deviceIP));
            }
            viewer.deviceFound(name, 1, ip, deviceType, deviceSN);
        }

        public override void scan()
        {
#if DEBUG
            selfTest();
#endif
            sendBroadcast(requestPort);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            HanwhaHeader header;
            byte[] result;

            header = new HanwhaHeader();
            header.packet_type = packet_type_request;

            result = header.GetBytes();

            return result;
        }
    }
}
