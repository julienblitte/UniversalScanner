using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Windows.Forms;
using System.Threading;
using System.Runtime.InteropServices;
using System.Drawing;

namespace UniversalScanner
{
    class Dahua1 : ScanEngine
    {
        protected const UInt16 magicQuery = 0x01a3;
        protected const UInt16 magicResponse = 0x00b3;

        protected const int port = 5050;

        protected bool _quirk = false;
        public bool quirk { get { return _quirk; } }

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

        [StructLayout(LayoutKind.Explicit, Size = 120, CharSet = CharSet.Ansi)]
        public struct Dahua1Section1
        {
            [FieldOffset(0)] public UInt16 headerMagic;   // 0x00b3 for answer, 0x01a3 fo discovery
            /* not 4-bytes aligned */
            [FieldOffset(2)] public UInt16 section2Len;
            [FieldOffset(4)] public UInt32 _04_value;      // 0x58 for answer, 0x00 for discovery
            [FieldOffset(8)] public UInt32 _08_reserved;
            [FieldOffset(12)] public UInt32 _0C_reserved;
            [FieldOffset(16)] public UInt32 protocolVersion;    // 0x02 for answer
            [FieldOffset(20)] public UInt16 section3Len;
            /* not 4-bytes aligned */
            [FieldOffset(22)] public UInt16 _16_value;   // often 0x0000
            [FieldOffset(24)] public UInt32 _18_reserved;
            [FieldOffset(28)] public UInt32 _1C_reserved;
            [FieldOffset(32)] public UInt32 _20_value;
            [FieldOffset(36)] public UInt32 _24_value;
            [FieldOffset(40)] public String16bytes deviceType;
            [FieldOffset(56)] public UInt32 ip;
            [FieldOffset(60)] public UInt32 mask;
            [FieldOffset(64)] public UInt32 gateway;
            [FieldOffset(68)] public UInt32 dns;

            [FieldOffset(72)] public UInt32 _48_value;
            [FieldOffset(76)] public UInt32 _4C_value;
            [FieldOffset(80)] public UInt32 _50_value;
            [FieldOffset(84)] public UInt32 _54_value;
            [FieldOffset(88)] public UInt32 _58_value;
            [FieldOffset(92)] public UInt32 _5C_value;
            [FieldOffset(96)] public UInt32 _60_value;
            [FieldOffset(100)] public UInt32 _64_value;
            [FieldOffset(104)] public UInt32 _68_value;
            [FieldOffset(108)] public UInt32 _6C_value;
            [FieldOffset(112)] public UInt32 _70_value;
            [FieldOffset(116)] public UInt32 _74_value;
        }

        protected byte[] discover = {
            0xa3, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        public Dahua1()
        {
            if (listenUdpGlobal(port) == -1)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: Dahua protocol v1: Failback to quirk mode");
                _quirk = true;

                listenUdpInterfaces();
            }
        }

        public override void scan()
        {
#if DEBUG
            selfTest("Dahua1.selftest");
#endif
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return discover;
        }

        private UInt32 dtohl(UInt32 value)
        {
            if (!BitConverter.IsLittleEndian)
            {
                value = value << 24
                    | ((value << 8) & 0x00ff0000)
                    | ((value >> 8) & 0x0000ff00)
                    | (value  >> 24);
            }

            return value;
        }

        private UInt16 dtohs(UInt16 value)
        {
            if (!BitConverter.IsLittleEndian)
            {
                value = (UInt16)((value << 8) | (value  >> 8));
            }

            return value;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            Dahua1Section1 section1;
            UInt16 section2Len;
            UInt16 section3Len;

            int deviceMacSize;

            UInt32 deviceIP;

            string deviceIPStr, deviceModel, deviceSerial;
            byte[] deviceTypeArray, deviceMacArray;
            byte[] section3Array;

            int index;

            deviceMacSize = 17; // "00:11:22:33:44:55".Length()

            // section 1:
            section1 = data.GetStruct<Dahua1Section1>();

            if (dtohl(section1.headerMagic) != magicResponse)
            {
                return;
            }

            // IP Address
            deviceIP = NetworkUtils.ntohl(section1.ip);
            deviceIPStr = String.Format("{0}.{1}.{2}.{3}", 
                (byte)((deviceIP >> 24) & 0xFF),
                (byte)((deviceIP >> 16) & 0xFF),
                (byte)((deviceIP >> 8) & 0xFF),
                (byte)((deviceIP) & 0xFF)
            );

            // device type
            deviceModel = Encoding.UTF8.GetString(section1.deviceType);

            section2Len = dtohs(section1.section2Len);
            section3Len = dtohs(section1.section3Len);

            // section 2:
            // mac Address
            deviceMacSize = Math.Min(deviceMacSize, section2Len);
            deviceMacArray = new byte[deviceMacSize];
            index = typeof(Dahua1Section1).StructLayoutAttribute.Size;
            Array.Copy(data, index, deviceMacArray, 0, deviceMacSize);
            index += deviceMacArray.Length;
            deviceSerial = Encoding.UTF8.GetString(deviceMacArray);

            // we still have more data in section 2
            if (section2Len > deviceMacSize)
            {
                // if deviceType from section2, replace deviceType with this one
                deviceTypeArray = new byte[section2Len - deviceMacSize];
                Array.Copy(data, index, deviceTypeArray, 0, deviceTypeArray.Length);
                index += deviceTypeArray.Length;
                deviceModel = Encoding.UTF8.GetString(deviceTypeArray);
            }

            // section 3:
            if (section3Len > 0)
            {
                Dictionary<string, string> values;

                section3Array = new byte[section3Len];
                Array.Copy(data, index, section3Array, 0, section3Array.Length);
                index += section3Array.Length;

                values = parseSection3(data);
                if (values.ContainsKey("SerialNo"))
                {
                    deviceSerial = values["SerialNo"];
                }
            }

            viewer.deviceFound(name, 1, deviceIPStr, deviceModel, deviceSerial);
        }

        Dictionary<string, string>parseSection3(byte[] data)
        {
            Dictionary<string, string> result;
            string str;
            string[] lines;

            result = new Dictionary<string, string>();
            str = Encoding.UTF8.GetString(data);

            lines = str.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach(var l in lines)
            {
                int s;

                s = l.IndexOf(':');
                if (s >= 0)
                {
                    result.Add(l.Substring(0, s), l.Substring(s+1));
                }
            }

            return result;
        }
    }
}

