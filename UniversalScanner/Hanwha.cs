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

        [StructLayout(LayoutKind.Explicit, Size = 172, CharSet = CharSet.Ansi)]
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

        /*
        Request 1:
        packet_type  [01]
                     [ad 2c da 75 c6 6e e0 fa a8 5d 6c b7 98 fa 9b 81 4f 11]
        mac_adress   [00 01 00 00 00 00 00 00 00 01 00 00 00 4c f8 40 00 00]
        ip_address   [00 00 00 00 00 00 00 10 60 00 80 01 00 00 00 1c]
        ip_mask      [00 12 00 b0 6d 5f 02 42 00 00 00 98 ef 19 00 e0]
        ip_gw        [00 ab 76 c8 18 5f 02 fe ff ff ff 00 00 5f 02 6d]
                     [00 a9 76 0c ef 19 00 16 dc 06 77 00 00 00 00 00 00 00 00 70 e2 88 13 00]
        device_name  [00 45 00 ec 7a 45 00 10 ef 19]
        url          [00 88 13 10 27 2e 27 24 27 1a 27 42 27 ec 7a 45 00 00 00 00 00 c4 7a 45 00 01 00 00 00 54 ef 19 00 a5 96 41 00 c5 96 41 00 e2 0b cc af 00 00 00 00 00 00 00 00]
                     [58 ef 19 00 dc 66 40 00 78 ef 19 00 e8 03 00 00 58 fe 19 00 d8 f7 19 00 a4 ef]
                     [19 00 3f ea 40 00 5a ea 40 00 12 0b cc af 10 60 00 80 82 0a 21 00 01 00 00 00 c8 18 5f 02 01 00
                     [00 00 d8 f7 19 00 00 00 00 00 a4 ef 19 00 56 90 40 00 70 e2 65 00 00 00 00 00 64 ef 19 00 e4 ef

        Request 2:
        packet_type  [01]
                     [68 79 fc 58 f3 b4 e8 97 51 a3 9c a9 98 fa 9b 81 4f 11]
        mac_adress   [00 00 00 00 00 00 00 00 00 11 60 00 80 01 00 00 00 6e]
        ip_address   [00 03 00 ff ff ff ff db 4d b3 75 f0 eb 19 00 a0]
        ip_mask      [00 b5 75 ee 91 95 18 fe ff ff ff 50 eb 19 00 3d]
        ip_gw        [00 b3 75 fc 38 41 00 00 00 00 00 f0 00 00 00 00]
                     [00 00 00 00 00 00 00 00 60 3c 00 01 00 00 00 c0 a1 fb 00 6e 07 88 13 00]
        device_name  [00 00 00 d0 eb 19 00 00 00 00]
        url          [00 88 13 10 27 2e 27 24 27 1a 27 42 27 01 00 00 00 6e 07 03 00 00 00 00 00 aa eb 36 6d 00 00 00 40 00 00 00 00 fc 38 41 00 08 00 00 c0 80 eb 19 00 6d 9d b4 75]
        c0 a1 fb 00
        00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
        60 f4 19 00 01 00 00 00 84 eb 19 00 c6 6c 41 00
        00 68 3c 00 98 eb 19 00 76 78 41 00 6e 07 03 00
        f0 00 00 00 00 00 00 00 01 00 00 00 b0 eb 19 00
        0e 7f 40 00 d0 eb 19 00 09 04 00 00 38 fe 19 00
        60 f4 19 00 fc eb

        Answer:
        packet_type [0b]
                    [ad 2c da 75 c6 6e e0 fa a8 5d 6c b7 98 fa 9b 81 4f 11]
        mac_adress  [30 30 3a 31 36 3a 36 43 3a 37 44 3a 37 35 3a 36 45 00]
        ip_address  [31 37 32 2e 31 36 2e 31 32 35 2e 35 35 00 00 00]
        ip_mask     [32 35 35 2e 32 35 35 2e 30 2e 30 00 00 00 00 00]
        ip_gw       [31 37 32 2e 31 36 2e 30 2e 31 00 00 00 00 00 00]
                    [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e2 50 00 00]
        device_name [53 4e 44 2d 36 30 38 33 00 00]
                    [00 50 00 a8 11 2e 27 24 27 1a 27 42 27 00]
        url         [68 74 74 70 3a 2f 2f 31 37 32 2e 31 36 2e 31 32 35 2e 35 35 2f 69 6e 64 65 78 2e 68 74 6d 00 00 00 00 00 00 00 00 00]
                    [58 ef 19 00 dc 66 40 00 78 ef 19 00 e8 03 00 00 58 fe 19 00 d8 f7 19 00 a4 ef]
                    [19 00 3f ea 40 00 5a ea 40 00 12 0b cc af 10 60 00 80 82 0a 21 00 01 00 00 00 c8 18 5f 02 01 00]
                    [00 00 d8 f7 19 00 00 00 00 00 a4 ef 19 00 56 90 40 00 70 e2 65 00 00 00 00 00 64 ef 19 00 e4 ef]


        */

        public Hanwha()
        {
            listenUdpInterfaces();
        }

        private string extractString(object source, int size)
        {
            IntPtr ptr;
            byte [] stringArray;
            StringBuilder builder;

            ptr = Marshal.AllocHGlobal(size);
            stringArray = new byte[size];
            try
            {
                Marshal.StructureToPtr(source, ptr, false);
                Marshal.Copy(ptr, stringArray, 0, size);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            // deviceType from section1
            builder = new StringBuilder();
            for (int i = 0; i < stringArray.Length; i++)
            {
                if (stringArray[i] == 0)
                    break;
                builder.Append(stringArray[i]);
            }
            return builder.ToString();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            HanwhaHeader header;
            int headerSize;
            string deviceIP, deviceType, deviceSN;

            headerSize = Marshal.SizeOf(typeof(HanwhaHeader));

            IntPtr ptr = Marshal.AllocHGlobal(headerSize);
            try
            {
                Marshal.Copy(data, 0, ptr, headerSize);
                header = Marshal.PtrToStructure<HanwhaHeader>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            deviceIP = extractString(header.ip_address, Marshal.SizeOf(header.ip_address));
            deviceType = extractString(header.device_type, Marshal.SizeOf(header.ip_address));
            deviceSN = extractString(header.mac_address, Marshal.SizeOf(header.ip_address));

            viewer.deviceFound(name, deviceIP, deviceType, deviceSN);
        }

        public override void scan()
        {
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            HanwhaHeader header;
            int headerSize;
            byte[] result;
            IntPtr ptr;

            header = new HanwhaHeader();
            header.packet_type = packet_type_request;

            headerSize = Marshal.SizeOf(header);
            result = new byte[headerSize];

            ptr = Marshal.AllocHGlobal(headerSize);
            try
            {
                Marshal.StructureToPtr<HanwhaHeader>(header, ptr, false);
                Marshal.Copy(ptr, result, 0, headerSize);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            return result;
        }

    }
}
