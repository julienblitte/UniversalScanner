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

        protected UInt32 magic = 0x9939a427;
        protected UInt32 requestMagic = 0xff0006de;

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
                return Color.DarkRed.ToArgb();
            }
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
        };

        [StructLayout(LayoutKind.Explicit, Size = 32, CharSet = CharSet.Ansi)]
        public struct BoschBinaryResponse
        {
            [FieldOffset(0)] public UInt32 magic;
            [FieldOffset(4)] public UInt32 transactionID;
            [FieldOffset(8)] public MacAddress mac;
            [FieldOffset(14)] public byte _13_value;
            [FieldOffset(15)] public byte _14_value;
            [FieldOffset(16)] public UInt32 ip;
            [FieldOffset(20)] public UInt32 mask;
            [FieldOffset(24)] public UInt32 gateway;
            [FieldOffset(28)] public byte _28_value;
            [FieldOffset(29)] public byte _29_value;
            [FieldOffset(20)] public byte _30_value;
            [FieldOffset(31)] public byte _31_value;
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
            listenUdpGlobal(1758);
            listenUdpInterfaces();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string deviceIPStr, deviceTypeStr, deviceMac;

            // xml is much bigger
            if (data.Length == typeof(BoschBinaryResponse).StructLayoutAttribute.Size)
            {
                BoschBinaryResponse binary;
                IntPtr ptr;
                int binarySize;
                UInt32 ip;

                binarySize = Marshal.SizeOf(typeof(BoschBinaryResponse));

                ptr = Marshal.AllocHGlobal(binarySize);
                try
                {
                    Marshal.Copy(data, 0, ptr, binarySize);
                    binary = Marshal.PtrToStructure<BoschBinaryResponse>(ptr);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }

                if (ntohl(binary.magic) != magic)
                {
                    Trace.WriteLine("Warning: Bosch.reciever(): Packet with wrong header.");
                    return;
                }

                ip = ntohl(binary.ip);
                deviceIPStr = String.Format("{0}.{1}.{2}.{3}",
                    (byte)((ip >> 24) & 0xFF),
                    (byte)((ip >> 16) & 0xFF),
                    (byte)((ip >> 8) & 0xFF),
                    (byte)((ip) & 0xFF)
                );

                deviceMac = String.Format("{0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}", binary.mac.byte0, binary.mac.byte1, binary.mac.byte2,
                                            binary.mac.byte3, binary.mac.byte4, binary.mac.byte5);

                deviceTypeStr = name;

                viewer.deviceFound(name, 1, deviceIPStr, deviceTypeStr, deviceMac);
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
                if (m.Groups.Count == 2)
                {
                    deviceIPStr = m.Groups[1].Value;
                }

                deviceTypeStr = "";
                m = type.Match(xml);
                if (m.Groups.Count == 2)
                {
                    deviceTypeStr = m.Groups[1].Value;
                }

                deviceMac = "";
                m = mac.Match(xml);
                if (m.Groups.Count == 2)
                {
                    deviceMac = m.Groups[1].Value;
                }

                viewer.deviceFound(name, 2, deviceIPStr, deviceTypeStr, deviceMac);
            }
        }

        public override void scan()
        {
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            BoschRequest request;
            int size;
            IntPtr ptr;
            byte[] result;
            DateTime date;

            date = DateTime.UtcNow;

            request = new BoschRequest();
            request.magic = htonl(magic);
            request.transactionID = htonl((UInt32)
                ((date.Hour << 24) | (date.Minute << 16) | 
                (date.Second << 8) | (date.Millisecond / 10)
                ));
            request.requestMagic = htonl(requestMagic);

            size = Marshal.SizeOf(request);
            result = new byte[size];

            ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(request, ptr, true);
                Marshal.Copy(ptr, result, 0, size);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            return result;
        }
    }
}
