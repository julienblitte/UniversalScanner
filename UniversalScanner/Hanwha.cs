using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class Hanwha : ScanEngine
    {
        protected int port = 7701;
        protected int answerPort = 7711;

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

        const byte packet_type_request = 0x01;
        const byte packet_type_reply = 0x0b;

        [StructLayout(LayoutKind.Explicit, Size = 10, CharSet = CharSet.Ansi)]
        public struct String10bytes
        {
            [FieldOffset(0)] public byte byte00;
            [FieldOffset(1)] public byte byte01;
            [FieldOffset(2)] public byte byte02;
            [FieldOffset(3)] public byte byte03;
            [FieldOffset(4)] public byte byte04;
            [FieldOffset(5)] public byte byte05;
            [FieldOffset(6)] public byte byte06;
            [FieldOffset(7)] public byte byte07;
            [FieldOffset(8)] public byte byte08;
            [FieldOffset(9)] public byte byte09;
            [FieldOffset(10)] public byte byte0A;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16, CharSet = CharSet.Ansi)]
        public struct String16bytes
        {
            [FieldOffset(0)] public byte byte00;
            [FieldOffset(1)] public byte byte01;
            [FieldOffset(2)] public byte byte02;
            [FieldOffset(3)] public byte byte03;
            [FieldOffset(4)] public byte byte04;
            [FieldOffset(5)] public byte byte05;
            [FieldOffset(6)] public byte byte06;
            [FieldOffset(7)] public byte byte07;
            [FieldOffset(8)] public byte byte08;
            [FieldOffset(9)] public byte byte09;
            [FieldOffset(10)] public byte byte0A;
            [FieldOffset(11)] public byte byte0B;
            [FieldOffset(12)] public byte byte0C;
            [FieldOffset(13)] public byte byte0D;
            [FieldOffset(14)] public byte byte0E;
            [FieldOffset(15)] public byte byte0F;
        }

        [StructLayout(LayoutKind.Explicit, Size = 18, CharSet = CharSet.Ansi)]
        public struct String18bytes
        {
            [FieldOffset(0)] public byte byte00;
            [FieldOffset(1)] public byte byte01;
            [FieldOffset(2)] public byte byte02;
            [FieldOffset(3)] public byte byte03;
            [FieldOffset(4)] public byte byte04;
            [FieldOffset(5)] public byte byte05;
            [FieldOffset(6)] public byte byte06;
            [FieldOffset(7)] public byte byte07;
            [FieldOffset(8)] public byte byte08;
            [FieldOffset(9)] public byte byte09;
            [FieldOffset(10)] public byte byte0A;
            [FieldOffset(11)] public byte byte0B;
            [FieldOffset(12)] public byte byte0C;
            [FieldOffset(13)] public byte byte0D;
            [FieldOffset(14)] public byte byte0E;
            [FieldOffset(15)] public byte byte0F;
            [FieldOffset(16)] public byte byte10;
            [FieldOffset(17)] public byte byte11;
        }

        [StructLayout(LayoutKind.Explicit, Size = 39, CharSet = CharSet.Ansi)]
        public struct String39bytes
        {
            [FieldOffset(0)] public byte byte00;
            [FieldOffset(1)] public byte byte01;
            [FieldOffset(2)] public byte byte02;
            [FieldOffset(3)] public byte byte03;
            [FieldOffset(4)] public byte byte04;
            [FieldOffset(5)] public byte byte05;
            [FieldOffset(6)] public byte byte06;
            [FieldOffset(7)] public byte byte07;
            [FieldOffset(8)] public byte byte08;
            [FieldOffset(9)] public byte byte09;
            [FieldOffset(10)] public byte byte0A;
            [FieldOffset(11)] public byte byte0B;
            [FieldOffset(12)] public byte byte0C;
            [FieldOffset(13)] public byte byte0D;
            [FieldOffset(14)] public byte byte0E;
            [FieldOffset(15)] public byte byte0F;
            [FieldOffset(16)] public byte byte10;
            [FieldOffset(17)] public byte byte11;
            [FieldOffset(18)] public byte byte12;
            [FieldOffset(19)] public byte byte13;
            [FieldOffset(20)] public byte byte14;
            [FieldOffset(21)] public byte byte15;
            [FieldOffset(22)] public byte byte16;
            [FieldOffset(23)] public byte byte17;
            [FieldOffset(24)] public byte byte18;
            [FieldOffset(25)] public byte byte19;
            [FieldOffset(26)] public byte byte1A;
            [FieldOffset(27)] public byte byte1B;
            [FieldOffset(28)] public byte byte1C;
            [FieldOffset(29)] public byte byte1D;
            [FieldOffset(30)] public byte byte1E;
            [FieldOffset(31)] public byte byte1F;
            [FieldOffset(32)] public byte byte20;
            [FieldOffset(33)] public byte byte21;
            [FieldOffset(34)] public byte byte22;
            [FieldOffset(35)] public byte byte23;
            [FieldOffset(36)] public byte byte24;
            [FieldOffset(37)] public byte byte25;
            [FieldOffset(38)] public byte byte26;
        }

        [StructLayout(LayoutKind.Explicit, Size = 262, CharSet = CharSet.Ansi)]
        public struct HanwhaHeader
        {
            [FieldOffset(0)] public byte packet_type;   // 0x01 for request, 0x0b for answer
            [FieldOffset(1)] public byte _01_value;
            [FieldOffset(2)] public byte _02_value;
            [FieldOffset(3)] public byte _03_value;
            [FieldOffset(4)] public byte _04_value;
            [FieldOffset(5)] public byte _05_value;
            [FieldOffset(6)] public byte _06_value;
            [FieldOffset(7)] public byte _07_value;
            [FieldOffset(8)] public byte _08_value;
            [FieldOffset(9)] public byte _09_value;
            [FieldOffset(10)] public byte _0A_value;
            [FieldOffset(11)] public byte _0B_value;
            [FieldOffset(12)] public byte _0C_value;
            [FieldOffset(13)] public byte _0D_value;
            [FieldOffset(14)] public byte _0E_value;
            [FieldOffset(15)] public byte _0F_value;
            [FieldOffset(16)] public byte _10_value;
            [FieldOffset(17)] public byte _11_value;
            [FieldOffset(18)] public byte _12_value;
            [FieldOffset(19)] public String18bytes mac_address;
            [FieldOffset(37)] public String16bytes ip_address;
            [FieldOffset(53)] public String16bytes ip_mask;
            [FieldOffset(69)] public String16bytes ip_gw;
            [FieldOffset(85)] public byte _55_value;
            [FieldOffset(86)] public byte _56_value;
            [FieldOffset(87)] public byte _57_value;
            [FieldOffset(88)] public byte _58_value;
            [FieldOffset(89)] public byte _59_value;
            [FieldOffset(90)] public byte _5A_value;
            [FieldOffset(91)] public byte _5B_value;
            [FieldOffset(92)] public byte _5C_value;
            [FieldOffset(93)] public byte _5D_value;
            [FieldOffset(94)] public byte _5E_value;
            [FieldOffset(95)] public byte _5F_value;
            [FieldOffset(96)] public byte _60_value;
            [FieldOffset(97)] public byte _61_value;
            [FieldOffset(98)] public byte _62_value;
            [FieldOffset(99)] public byte _63_value;
            [FieldOffset(100)] public byte _64_value;
            [FieldOffset(101)] public byte _65_value;
            [FieldOffset(102)] public byte _66_value;
            [FieldOffset(103)] public byte _67_value;
            [FieldOffset(104)] public byte _68_value;
            [FieldOffset(105)] public byte _69_value;
            [FieldOffset(106)] public byte _6A_value;
            [FieldOffset(107)] public byte _6B_value;
            [FieldOffset(108)] public byte _6C_value;
            [FieldOffset(109)] public String10bytes device_type;
            [FieldOffset(119)] public byte _77_value;
            [FieldOffset(120)] public byte _78_value;
            [FieldOffset(121)] public byte _79_value;
            [FieldOffset(122)] public byte _7A_value;
            [FieldOffset(123)] public byte _7B_value;
            [FieldOffset(124)] public byte _7C_value;
            [FieldOffset(125)] public byte _7D_value;
            [FieldOffset(126)] public byte _7E_value;
            [FieldOffset(127)] public byte _7F_value;
            [FieldOffset(128)] public byte _80_value;
            [FieldOffset(129)] public byte _81_value;
            [FieldOffset(130)] public byte _82_value;
            [FieldOffset(131)] public byte _83_value;
            [FieldOffset(132)] public byte _84_value;
            [FieldOffset(133)] public String39bytes url;
            [FieldOffset(172)] public byte _AC_value;
            [FieldOffset(173)] public byte _AD_value;
            [FieldOffset(174)] public UInt32 _padding1;
            [FieldOffset(178)] public UInt32 _padding2;
            [FieldOffset(182)] public UInt32 _padding3;
            [FieldOffset(186)] public UInt32 _padding4;
            [FieldOffset(190)] public UInt32 _padding5;
            [FieldOffset(194)] public UInt32 _padding6;
            [FieldOffset(198)] public UInt32 _padding7;
            [FieldOffset(202)] public UInt32 _padding8;
            [FieldOffset(206)] public UInt32 _padding9;
            [FieldOffset(210)] public UInt32 _padding10;
            [FieldOffset(214)] public UInt32 _padding11;
            [FieldOffset(218)] public UInt32 _padding12;
            [FieldOffset(222)] public UInt32 _padding13;
            [FieldOffset(226)] public UInt32 _padding14;
            [FieldOffset(230)] public UInt32 _padding15;
            [FieldOffset(234)] public UInt32 _padding16;
            [FieldOffset(238)] public UInt32 _padding17;
            [FieldOffset(242)] public UInt32 _padding18;
            [FieldOffset(246)] public UInt32 _padding19;
            [FieldOffset(250)] public UInt32 _padding20;
            [FieldOffset(254)] public UInt32 _padding21;
            [FieldOffset(258)] public UInt32 _padding22;
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
                Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Hawha.reciever(): Invalid ipv4 format: {0}", deviceIP));
            }
            viewer.deviceFound(name, 1, ip, deviceType, deviceSN);
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
            HanwhaHeader header;
            byte[] result;

            header = new HanwhaHeader();
            header.packet_type = packet_type_request;

            result = header.GetBytes();

            return result;
        }
    }
}