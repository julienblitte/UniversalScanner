using System;
using System.IO;
using System.Runtime.InteropServices;

namespace selftest2pcap
{
    class Program
    {
        [DllImport("wsock32.dll")]
        public static extern UInt32 ntohl(UInt32 value);
        [DllImport("wsock32.dll")]
        public static extern UInt32 htonl(UInt32 value);
        [DllImport("wsock32.dll")]
        public static extern UInt16 ntohs(UInt16 value);
        [DllImport("wsock32.dll")]
        public static extern UInt16 htons(UInt16 value);


        [StructLayout(LayoutKind.Explicit, Size = 24, CharSet = CharSet.Ansi)]
        public struct PcapHeader
        {
            [FieldOffset(0)] public UInt32 magic;
            [FieldOffset(4)] public UInt16 major;
            [FieldOffset(6)] public UInt16 minor;
            [FieldOffset(8)] public UInt32 timezone;
            [FieldOffset(12)] public UInt32 timestamp;
            [FieldOffset(16)] public UInt32 maxLength;
            [FieldOffset(20)] public UInt32 linkLayer;

            public PcapHeader(int defaultInit)
            {
                magic = 0xa1b2c3d4;
                major = 0x0002;
                minor = 0x0004;
                timezone = 0;
                timestamp = 0;
                maxLength = 1500;
                linkLayer = 1;
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 16, CharSet = CharSet.Ansi)]
        public struct PcapItemHeader
        {
            [FieldOffset(0)] public UInt32 second;
            [FieldOffset(4)] public UInt32 microsecond;
            [FieldOffset(8)] public UInt32 length;
            [FieldOffset(12)] public UInt32 untruncated;

            public PcapItemHeader(DateTime captureTime, UInt32 len)
            {
                second = (UInt32)(captureTime.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                microsecond = 0;
                length = len;
                untruncated = length;
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 6, CharSet = CharSet.Ansi)]
        public struct EthernetAddress
        {
            [FieldOffset(0)] public Byte byte0;
            [FieldOffset(1)] public Byte byte1;
            [FieldOffset(2)] public Byte byte2;
            [FieldOffset(3)] public Byte byte3;
            [FieldOffset(4)] public Byte byte4;
            [FieldOffset(5)] public Byte byte5;
        }

        [StructLayout(LayoutKind.Explicit, Size = 14, CharSet = CharSet.Ansi)]
        public struct Ethernet
        {
            [FieldOffset(0)] public EthernetAddress source;
            [FieldOffset(6)] public EthernetAddress destination;
            [FieldOffset(12)] public UInt16 type;

            public Ethernet(int defaultInit)
            {
                source = new EthernetAddress();
                destination = new EthernetAddress();
                type = htons(0x0800);
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 20, CharSet = CharSet.Ansi)]
        public struct IPv4
        {
            [FieldOffset(0)] public Byte versionIHL;
            [FieldOffset(1)] public Byte ToS;
            [FieldOffset(2)] public UInt16 totalLength;

            [FieldOffset(4)] public UInt16 identification;
            [FieldOffset(6)] public UInt16 flagsFragment;
            [FieldOffset(8)] public Byte TTL;
            [FieldOffset(9)] public Byte protocol;
            [FieldOffset(10)] public UInt16 checksum;
            [FieldOffset(12)] public UInt32 source;
            [FieldOffset(16)] public UInt32 destination;

            public IPv4(UInt16 length)
            {
                versionIHL = (4 << 4) |  5;
                totalLength = htons((UInt16)(length + typeof(IPv4).StructLayoutAttribute.Size));
                ToS = 0;
                identification = htons(0);
                flagsFragment = htons(0);
                TTL = 254;
                protocol = 0x11; // UDP
                checksum = 0;
                source = htonl(0x7F000001); // 127.0.0.1
                destination = htonl(0x7F000001); // 127.0.0.1
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 8, CharSet = CharSet.Ansi)]
        public struct UDP
        {
            [FieldOffset(0)] public UInt16 sourcePort;
            [FieldOffset(2)] public UInt16 destPort;
            [FieldOffset(4)] public UInt16 totalLength;
            [FieldOffset(6)] public UInt16 checksum;

            public UDP(UInt16 port, UInt16 length)
            {
                sourcePort = htons(port);
                destPort = htons(port);
                totalLength = htons((UInt16)(length + typeof(UDP).StructLayoutAttribute.Size));
                checksum = 0;
            }
        }


        static void usage()
        {
            Console.WriteLine("Convert a selftest file into pcap file");
            Console.WriteLine(String.Format("Usage: {0} <input.selftest> <output.pcap> [udp.destport]", "selftest2pcap"));
        }

        static void Main(string[] args)
        {
            PcapHeader fileHeader;
            PcapItemHeader packetHeader;
            Ethernet packetEthernet;
            IPv4 packetIP;
            UDP packetUDP;
            UInt16 destPort;
            byte[] payloadFileHeader, payloadItemHeader, payloadEthernet, payloadIP, payloadUDP, payloadData;
            DateTime captureTime;
            byte[] payload;
            int index;

            string source, dest;

            if (args.Length < 2)
            {
                usage();
                return;
            }

            if (args.Length > 2)
            {
                if (!UInt16.TryParse(args[2], out destPort))
                {
                    Console.WriteLine(String.Format("Error: The value {0} is not a valid port number!", args[2]));
                    usage();
                    return;
                }
            }
            else
            {
                destPort = 0;
            }

            source = args[0];
            dest = args[1];



            if (!File.Exists(source))
            {
                Console.WriteLine(String.Format("Error: File {0} does not exists!", source));
            }
            if (File.Exists(dest))
            {
                Console.WriteLine(String.Format("Error: File {0} already exists! Please delete it first.", dest));
            }

            try
            {
                /* load payload */
                payloadData = File.ReadAllBytes(source);
                captureTime = File.GetLastWriteTimeUtc(source);

                /* UDP */
                packetUDP = new UDP(destPort, (UInt16)payloadData.Length);
                payloadUDP = packetUDP.GetBytes();

                /* ipv4 */
                packetIP = new IPv4((UInt16)(payloadUDP.Length + payloadData.Length));
                payloadIP = packetIP.GetBytes();

                /* ethernet */
                packetEthernet = new Ethernet(1);
                payloadEthernet = packetEthernet.GetBytes();

                /* pcap packet header */
                packetHeader = new PcapItemHeader(captureTime, (UInt32)(payloadEthernet.Length + payloadIP.Length + payloadUDP.Length + payloadData.Length));
                payloadItemHeader = packetHeader.GetBytes();

                /* pcap file header */
                fileHeader = new PcapHeader(1);
                payloadFileHeader = fileHeader.GetBytes();

                payload = new byte[payloadFileHeader.Length + payloadItemHeader.Length + payloadEthernet.Length + payloadIP.Length + payloadUDP.Length + payloadData.Length];

                index = 0;
                payloadFileHeader.CopyTo(payload, index);
                index += payloadFileHeader.Length;

                payloadItemHeader.CopyTo(payload, index);
                index += payloadItemHeader.Length;

                payloadEthernet.CopyTo(payload, index);
                index += payloadEthernet.Length;

                payloadIP.CopyTo(payload, index);
                index += payloadIP.Length;

                payloadUDP.CopyTo(payload, index);
                index += payloadUDP.Length;

                payloadData.CopyTo(payload, index);
                index += payloadData.Length;

                File.WriteAllBytes(dest, payload);
            }
            catch (Exception e)
            {
                Console.WriteLine(String.Format("Error: Unable to convert '{0}' to '{1}'!", source, dest));
                Console.WriteLine(e.ToString());
                return;
            }

            Console.WriteLine(String.Format("'{0}' -> '{1}'", source, dest));
        }
    }
}
