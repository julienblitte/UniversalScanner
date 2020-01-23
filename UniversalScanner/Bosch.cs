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
        protected int port = 1757;

        protected byte[] discover = { 0x99, 0x39, 0xa4, 0x27, 0x60, 0x08, 0xad, 0x0a, 0xff, 0x00, 0x06, 0xde };
        protected UInt64 BoschMagic = 0x9939a4276008ad0a;

        protected int color = Color.DarkRed.ToArgb();

        [StructLayout(LayoutKind.Explicit, Size = 6, CharSet = CharSet.Ansi)]
        public struct MacAddress
        {
            [FieldOffset(0)] public byte byte0;
            [FieldOffset(1)] public byte byte1;
            [FieldOffset(2)] public byte byte2;
            [FieldOffset(3)] public byte byte3;
            [FieldOffset(4)] public byte byte4;
            [FieldOffset(5)] public byte byte5;
        };

        [StructLayout(LayoutKind.Explicit, Size = 32, CharSet = CharSet.Ansi)]
        public struct BoschBinary
        {
            [FieldOffset(0)] public UInt64 magic;
            [FieldOffset(8)] public MacAddress mac;
            [FieldOffset(14)] public byte _13_value;
            [FieldOffset(15)] public byte _14_value;
            [FieldOffset(16)] public UInt32 ip;
            [FieldOffset(20)] public UInt32 mask;
            [FieldOffset(24)] public UInt32 gatway;
            [FieldOffset(28)] public byte _28_value;
            [FieldOffset(29)] public byte _29_value;
            [FieldOffset(20)] public byte _30_value;
            [FieldOffset(31)] public byte _31_value;
        };

        public Bosch()
        {
            listenUdpGlobal();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string deviceIPStr, deviceTypeStr, deviceMac;

            // xml is much bigger
            if (data.Length == typeof(BoschBinary).StructLayoutAttribute.Size)
            {
                BoschBinary binary;
                IntPtr ptr;
                int binarySize;

                binarySize = Marshal.SizeOf(typeof(BoschBinary));

                ptr = Marshal.AllocHGlobal(binarySize);
                try
                {
                    Marshal.Copy(data, 0, ptr, binarySize);
                    binary = Marshal.PtrToStructure<BoschBinary>(ptr);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }

                if (binary.magic != BoschMagic)
                {
                    Trace.WriteLine("Warning: Bosch.reciever(): Packet with wrong header.");
                    return;
                }

                deviceIPStr = String.Format("", binary.ip);
                deviceMac = String.Format("{0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}", binary.mac.byte0, binary.mac.byte1, binary.mac.byte2,
                                            binary.mac.byte3, binary.mac.byte4, binary.mac.byte5);

                deviceTypeStr = "Bosch binary";

                // postpone few seconds to prioritize XML instead binary
                ThreadPool.QueueUserWorkItem(deviceFoundDelayed, new deviceFoundParameters() {
                    viewer = viewer, deviceIPStr = deviceIPStr, deviceMac = deviceMac, deviceTypeStr = deviceTypeStr, color = color });
            }
            else
            {
                string xml;
                Regex type, ip, mac;
                Match m;

                xml = Encoding.UTF8.GetString(data);
                type = new Regex("<friendlyName>([^<]*)</friendlyName>");
                ip = new Regex("<unitIPAddress>([^<]*)</unitIPAddress>");
                mac = new Regex("<physAddress>([^<]*)</physAddress>");

                deviceIPStr = "";
                m = ip.Match(xml);
                if (m.Groups.Count >= 2)
                {
                    deviceIPStr = m.Captures[1].Value;
                }

                deviceTypeStr = "";
                m = type.Match(xml);
                if (m.Groups.Count >= 2)
                {
                    deviceTypeStr = m.Captures[1].Value;
                }

                deviceMac = "";
                m = mac.Match(xml);
                if (m.Groups.Count >= 2)
                {
                    deviceMac = m.Captures[1].Value;
                }

                viewer.deviceFound("bosh", deviceIPStr, deviceTypeStr, deviceMac, color);
            }
        }

        public struct deviceFoundParameters
        {
            public ScannerViewer viewer;
            public string deviceIPStr, deviceTypeStr, deviceMac;
            public int color;
        }
        static void deviceFoundDelayed(Object parameters)
        {
            deviceFoundParameters p;

            Thread.Sleep(1000);
            p = (deviceFoundParameters)parameters;
            p.viewer.deviceFound("bosh", p.deviceIPStr, p.deviceTypeStr, p.deviceMac, p.color);

        }

        public override void scan()
        {
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return discover;
        }
    }
}
