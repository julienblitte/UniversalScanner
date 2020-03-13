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
        protected int port = 5050;

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
            [FieldOffset(0)] public byte byte0;
            [FieldOffset(1)] public byte byte1;
            [FieldOffset(2)] public byte byte2;
            [FieldOffset(3)] public byte byte3;
            [FieldOffset(4)] public byte byte4;
            [FieldOffset(5)] public byte byte5;
            [FieldOffset(6)] public byte byte6;
            [FieldOffset(7)] public byte byte7;
            [FieldOffset(8)] public byte byte8;
            [FieldOffset(9)] public byte byte9;
            [FieldOffset(10)] public byte byteA;
            [FieldOffset(11)] public byte byteB;
            [FieldOffset(12)] public byte byteC;
            [FieldOffset(13)] public byte byteD;
            [FieldOffset(14)] public byte byteE;
            [FieldOffset(15)] public byte byteF;
        }

        [StructLayout(LayoutKind.Explicit, Size = 117, CharSet = CharSet.Ansi)]
        public struct Dahua1Section1
        {
            [FieldOffset(0)] public UInt16 headerMagic;   // 0x00b3 for answer, 0x01a3 fo discovery
            /* not 4-bytes aligned */
            [FieldOffset(2)] public Byte section2Len;
            /* not 4-bytes aligned */
            [FieldOffset(3)] public Byte _03_value;
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
                Trace.WriteLine("Warning: Dahua protocol v1: Failback to quirk mode");
                _quirk = true;

                listenUdpInterfaces();
            }
        }

        public override void scan()
        {
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return discover;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            Dahua1Section1 section1;
            int section1Size, deviceMacSize;
            IntPtr ptr;

            UInt32 deviceIP;
            Byte section2Len;

            string deviceIPStr, deviceTypeStr, deviceMac;
            byte[] deviceTypeArray, deviceMacArray;
            StringBuilder stringBuilder;

            int macAddressSize = 17;

            // section 1:
            section1Size = Marshal.SizeOf(typeof(Dahua1Section1));

            ptr = Marshal.AllocHGlobal(section1Size);
            try
            {
                Marshal.Copy(data, 0, ptr, section1Size);
                section1 = Marshal.PtrToStructure<Dahua1Section1>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            // build IP Address from section1
            deviceIP = (UInt32)IPAddress.NetworkToHostOrder((Int32)section1.ip);
            deviceIPStr = String.Format("{0}.{1}.{2}.{3}", 
                (byte)((deviceIP >> 24) & 0xFF),
                (byte)((deviceIP >> 16) & 0xFF),
                (byte)((deviceIP >> 8) & 0xFF),
                (byte)((deviceIP) & 0xFF)
            );

            // build device name from section1
            int deviceTypeSize = Marshal.SizeOf(typeof(String16bytes));

            ptr = Marshal.AllocHGlobal(deviceTypeSize);
            deviceTypeArray = new byte[deviceTypeSize];
            try
            {
                Marshal.StructureToPtr<String16bytes>(section1.deviceType, ptr, false);
                Marshal.Copy(ptr, deviceTypeArray, 0, deviceTypeSize);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            // deviceType from section1
            stringBuilder = new StringBuilder();
            for (int i=0; i < deviceTypeArray.Length; i++)
            {
                if (deviceTypeArray[i] == 0)
                    break;
                stringBuilder.Append(deviceTypeArray[i]);
            }
            deviceTypeStr = stringBuilder.ToString();


            // section 2:
            // retrieve mac from section 2
            section2Len = section1.section2Len;
            deviceMacSize = Math.Min(macAddressSize, section2Len);
            deviceMacArray = new byte[deviceMacSize];
            Array.Copy(data, section1Size, deviceMacArray, 0, deviceMacSize);
            deviceMac = Encoding.UTF8.GetString(deviceMacArray);


            // if deviceType from section2, replace deviceType with this one
            if (section2Len > deviceMacSize)
            {
                deviceTypeArray = new byte[section2Len - deviceMacSize];
                Array.Copy(data, section1Size + deviceMacSize, deviceTypeArray, 0, deviceTypeArray.Length);
                deviceTypeStr = Encoding.UTF8.GetString(deviceTypeArray);
            }

            viewer.deviceFound(name, deviceIPStr, deviceTypeStr, deviceMac);
        }
    }
}

