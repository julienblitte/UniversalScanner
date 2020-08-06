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
        private const int port = 5050;

        private const byte requestMagic = 0xa3;
        private const byte answerMagic = 0xb3;

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

        [StructLayout(LayoutKind.Explicit, Size = 0x78, CharSet = CharSet.Ansi)]
        public struct Dahua1Section1
        {
            [FieldOffset(0x00)] public byte headerMagic;   // 0xb3 for answer, 0xa3 fo discovery
            [FieldOffset(0x01)] public byte _byte_01;
            /* not 4-bytes aligned */
            [FieldOffset(0x02)] public byte section2Len;
            [FieldOffset(0x03)] public byte _byte_03;
            [FieldOffset(0x04)] public UInt32 packetType;      // 0x58 for answer, 0x00 for discovery
            [FieldOffset(0x08)] public UInt32 _reserved_08;
            [FieldOffset(0x0C)] public UInt32 _reserved_0C;
            [FieldOffset(0x10)] public UInt32 protocolVersion;    // 0x02 for answer
            [FieldOffset(0x14)] public UInt16 section3Len;
            /* not 4-bytes aligned */
            [FieldOffset(0x16)] public UInt16 _uint32_16;   // often 0x0000
            [FieldOffset(0x18)] public UInt32 _reserved_18;
            [FieldOffset(0x1C)] public UInt32 _reserved_1C;
            [FieldOffset(0x20)] public UInt32 _uint32_20;
            [FieldOffset(0x24)] public UInt32 _uint32_24;
            [FieldOffset(0x28)] public String16bytes deviceType;
            [FieldOffset(0x38)] public UInt32 ip;
            [FieldOffset(0x3C)] public UInt32 mask;
            [FieldOffset(0x40)] public UInt32 gateway;
            [FieldOffset(0x44)] public UInt32 dns;

            [FieldOffset(0x48)] public UInt32 _uint32_48;
            [FieldOffset(0x4C)] public UInt32 _uint32_4C;
            [FieldOffset(0x50)] public UInt32 _uint32_50;
            [FieldOffset(0x54)] public UInt32 _uint32_54;
            [FieldOffset(0x58)] public UInt32 _uint32_58;
            [FieldOffset(0x5C)] public UInt32 _uint32_5C;
            [FieldOffset(0x60)] public UInt32 _uint32_60;
            [FieldOffset(0x64)] public UInt32 _uint32_64;
            [FieldOffset(0x68)] public UInt32 _uint32_68;
            [FieldOffset(0x6C)] public UInt32 _uint32_6C;
            [FieldOffset(0x70)] public UInt32 _uint32_70;
            [FieldOffset(0x74)] public UInt32 _uint32_74;
        }

        private readonly byte[] discover = {
            0xa3, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        public Dahua1()
        {
            if (listenUdpGlobal(port) == -1)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua protocol v1: Failed to listen on port {0}", port));
            }
            listenUdpInterfaces();
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

        public override void reciever(IPEndPoint from, byte[] data)
        {
            Dahua1Section1 section1;
            int section1Len;
            byte section2Len;
            UInt16 section3Len;

            int deviceMacSize;

            UInt32 deviceIPv4;

            string deviceModel, deviceSerial, deviceIPv6;
            byte[] deviceTypeArray, deviceMacArray;
            byte[] section3Array;

            int index;

            section1Len = Marshal.SizeOf(typeof(Dahua1Section1));

            deviceMacSize = 17; // "00:11:22:33:44:55".Length()

            // section 1:
            if (data.Length < Marshal.SizeOf(typeof(Dahua1Section1)))
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua1.reciever(): Invalid packet size (less than section1) from {0}", from.ToString()));
                return;
            }

            section1 = data.GetStruct<Dahua1Section1>();

            if (section1.headerMagic != answerMagic)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua1.reciever(): Wrong header magic recieved from {0}", from.ToString()));
                return;
            }

            // IP Address
            deviceIPv4 = NetworkUtils.littleEndian32(section1.ip);

            // device type
            deviceModel = Encoding.UTF8.GetString(section1.deviceType);

            section2Len = section1.section2Len;
            section3Len = NetworkUtils.littleEndian16(section1.section3Len);

            if (section1Len + section2Len + section3Len != data.Length)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua1.reciever(): Packet has wrong size = {0} (expected was {1})", data.Length, section1Len + section2Len + section3Len));
                return;
            }

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
            deviceIPv6 = null;
            if (section3Len > 0)
            {
                Dictionary<string, string> values;

                section3Array = new byte[section3Len];
                Array.Copy(data, index, section3Array, 0, section3Array.Length);
                index += section3Array.Length;

                values = parseSection3(section3Array);
                if (values.ContainsKey("SerialNo"))
                {
                    deviceSerial = values["SerialNo"];
                }
                if (values.ContainsKey("IPv6Addr"))
                {
                    deviceIPv6 = values["IPv6Addr"];
                    if (deviceIPv6.Contains(';'))
                    {
                        var IPv6Split = deviceIPv6.Split(';');
                        deviceIPv6 = IPv6Split[0];
                    }
                    if (deviceIPv6.Contains('/'))
                    {
                        var IPv6Split = deviceIPv6.Split('/');
                        deviceIPv6 = IPv6Split[0];
                    }
                }
            }

            viewer.deviceFound(name, 1, new IPAddress(deviceIPv4), deviceModel, deviceSerial);

            if (deviceIPv6 != null)
            {
                IPAddress ip;
                if (IPAddress.TryParse(deviceIPv6, out ip))
                {
                    viewer.deviceFound(name, 2, ip, deviceModel, deviceSerial);
                }
                else
                {
                    Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Dahua1.reciever(): Invalid ipv6 format: {0}", deviceIPv6));
                }
            }

        }

        private Dictionary<string, string> parseSection3(byte[] data)
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
                    string key, value;

                    key = l.Substring(0, s);
                    value = l.Substring(s+1);

                    if (!result.ContainsKey(key))
                    {
                        result.Add(key, value);
                    }
                    else
                    {
                        result[key] = value;
                    }
                }
            }

            return result;
        }
    }
}

