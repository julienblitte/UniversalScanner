using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace JulienBlitte
{
    public class PcapFile
    {
        [DllImport("wsock32.dll")]
        public static extern UInt32 ntohl(UInt32 value);
        [DllImport("wsock32.dll")]
        public static extern UInt32 htonl(UInt32 value);
        [DllImport("wsock32.dll")]
        public static extern UInt16 ntohs(UInt16 value);
        [DllImport("wsock32.dll")]
        public static extern UInt16 htons(UInt16 value);

        private MemoryStream content;
        private string filename;

        private Dictionary<UInt16, UInt64> tcpWindows;

        public static readonly byte[] macManufacturer = { 0x02, 0x00, 0x00 };

        public PcapFile(string filename)
        {
            byte[] initData;

            this.filename = filename;
            content = new MemoryStream();

            if (File.Exists(this.filename))
            {
                initData = File.ReadAllBytes(filename);
                content.Write(initData, 0, initData.Length);
            }
            else
            {
                /* pcap file header */
                PcapHeader fileHeader;
                fileHeader = new PcapHeader(1);
                initData = fileHeader.GetBytes();
                content.Write(initData, 0, initData.Length);
                Save();
            }

            tcpWindows = new Dictionary<UInt16, UInt64>();
        }

        public void Save()
        {
            File.WriteAllBytes(filename, content.ToArray());
        }

        //htonl(0x7F000001); // 127.0.0.1
        public void Append(IPEndPoint source, IPEndPoint destination, ProtocolType protocol, byte[] payload, DateTime? timestamp=null)
        {
            PcapItemHeader packetHeader;
            Ethernet packetEthernet;
            IPv4 packetIP;

            byte[] sourceBytes, destinationBytes;

            byte[] payloadItemHeader, payloadEthernet, payloadIP, payloadTransport, payloadData;
            int index;

            switch (protocol)
            {
                case ProtocolType.Udp:
                    UDP packetUDP;
                    packetUDP = new UDP((UInt16)source.Port, (UInt16)destination.Port, (UInt16)payload.Length);
                    payloadTransport = packetUDP.GetBytes();
                    break;
                case ProtocolType.Tcp:
                    TCP packetTCP;
                    UInt16 connection1, connection2;

                    UInt64 seqAck;
                    UInt32 seq, ack;

                    connection1 = tcpConnectionId(source, destination);
                    connection2 = tcpConnectionId(destination, source);
                    if (tcpWindows.ContainsKey(connection1))
                    {
                        seqAck = tcpWindows[connection1];
                        seq = (UInt32)(seqAck >> 32);
                        ack = (UInt32)seqAck;
                    }
                    else
                    {
                        seq = 1;
                        ack = 1;
                        seqAck = ((UInt64)seq << 32) | ack;
                        tcpWindows.Add(connection1, seqAck);
                    }

                    packetTCP = new TCP((UInt16)source.Port, (UInt16)destination.Port, seq, ack);

                    seq += (UInt32)payload.Length;
                    seqAck = ((UInt64)seq << 32) | ack;
                    tcpWindows[connection1] = seqAck;

                    if (tcpWindows.ContainsKey(connection2))
                    {
                        seqAck = tcpWindows[connection2];
                        seq = (UInt32)(seqAck >> 32);
                        ack = (UInt32)payload.Length;

                        seqAck = ((UInt64)seq << 32) | ack;
                        tcpWindows[connection2] = seqAck;
                    }
                    else
                    {
                        seq = 1;
                        ack = (UInt32)payload.Length;

                        seqAck = ((UInt64)seq << 32) | ack;
                        tcpWindows.Add(connection2, seqAck);
                    }

                    payloadTransport = packetTCP.GetBytes();
                    break;
                case ProtocolType.IP:
                    payloadTransport = new byte[] { };
                    break;
                default:
                    throw new System.ArgumentException("This protocol is not supported", "protocol");
            }


            /* ipv4 */
            packetIP = new IPv4(source.Address, destination.Address, protocol, (UInt16)(payloadTransport.Length + payload.Length));
            payloadIP = packetIP.GetBytes();

            /* ethernet */
            sourceBytes = source.Address.GetAddressBytes();
            destinationBytes = destination.Address.GetAddressBytes();
            packetEthernet = new Ethernet(new byte[3] { sourceBytes[1], sourceBytes[2], sourceBytes[3] }, new byte[3] { destinationBytes[1], destinationBytes[2], destinationBytes[3] });
            payloadEthernet = packetEthernet.GetBytes();

            /* pcap packet header */
            if (timestamp == null)
            {
                timestamp = DateTime.UtcNow;
            }
            packetHeader = new PcapItemHeader((DateTime)timestamp, (UInt32)(payloadEthernet.Length + payloadIP.Length + payloadTransport.Length + payload.Length));
            payloadItemHeader = packetHeader.GetBytes();

            payloadData = new byte[payloadItemHeader.Length + payloadEthernet.Length + payloadIP.Length + payloadTransport.Length + payload.Length];

            index = 0;
            payloadItemHeader.CopyTo(payloadData, index);
            index += payloadItemHeader.Length;

            payloadEthernet.CopyTo(payloadData, index);
            index += payloadEthernet.Length;

            payloadIP.CopyTo(payloadData, index);
            index += payloadIP.Length;

            payloadTransport.CopyTo(payloadData, index);
            index += payloadTransport.Length;

            payload.CopyTo(payloadData, index);
            index += payload.Length;

            if (payloadData.Length != packetHeader.length + 16)
            {
                throw new Exception("Error of PCap. Possible bug");
            }

            content.Write(payloadData, 0, payloadData.Length);
        }

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
                microsecond = (UInt32)(captureTime.Subtract(new DateTime(1970, 1, 1))).Milliseconds * 1000;
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

            public Ethernet(byte[] _source, byte[] _destination)
            {
                source = new EthernetAddress();
                source.byte0 = macManufacturer[0];
                source.byte1 = macManufacturer[1];
                source.byte2 = macManufacturer[2];
                if (_source != null)
                {
                    if (_source.Length == 3)
                    {
                        source.byte3 = _source[0];
                        source.byte4 = _source[1];
                        source.byte5 = _source[2];
                    }
                }

                destination = new EthernetAddress();
                destination.byte0 = macManufacturer[0];
                destination.byte1 = macManufacturer[1];
                destination.byte2 = macManufacturer[2];
                if (_destination != null)
                {
                    if (_destination.Length == 3)
                    {
                        destination.byte3 = _destination[0];
                        destination.byte4 = _destination[1];
                        destination.byte5 = _destination[2];
                    }
                }

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

            public IPv4(IPAddress source, IPAddress destination, ProtocolType protocol, UInt16 length)
            {
                byte[] addr;

                versionIHL = (4 << 4) | 5;
                totalLength = htons((UInt16)(length + typeof(IPv4).StructLayoutAttribute.Size));
                ToS = 0;
                identification = htons(0);
                flagsFragment = htons(0);
                TTL = 254;
                this.protocol = (byte)protocol;
                checksum = 0;

                addr = source.GetAddressBytes();
                this.source = htonl((UInt32)((addr[0] << 24)|(addr[1] << 16)|(addr[2] << 8)|addr[3]));

                addr = destination.GetAddressBytes();
                this.destination = htonl((UInt32)((addr[0] << 24)|(addr[1] << 16)|(addr[2] << 8)|addr[3]));
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 8, CharSet = CharSet.Ansi)]
        public struct UDP
        {
            [FieldOffset(0)] public UInt16 sourcePort;
            [FieldOffset(2)] public UInt16 destPort;
            [FieldOffset(4)] public UInt16 totalLength;
            [FieldOffset(6)] public UInt16 checksum;

            public UDP(UInt16 sourcePort, UInt16 destPort, UInt16 length)
            {
                this.sourcePort = htons(sourcePort);
                this.destPort = htons(destPort);
                totalLength = htons((UInt16)(length + typeof(UDP).StructLayoutAttribute.Size));
                checksum = 0;
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 8, CharSet = CharSet.Ansi)]
        public struct TCP
        {
            [FieldOffset(0)] public UInt16 sourcePort;
            [FieldOffset(2)] public UInt16 destPort;
            [FieldOffset(4)] public UInt32 sequence;
            [FieldOffset(8)] public UInt32 acknowledge;
            [FieldOffset(12)] public UInt16 nextHeaderFlags;
            [FieldOffset(14)] public UInt16 window;
            [FieldOffset(16)] public UInt16 checksum;
            [FieldOffset(18)] public UInt16 urgent;

            public TCP(UInt16 sourcePort, UInt16 destPort, UInt32 seq, UInt32 ack)
            {
                UInt16 headerSize;

                headerSize = 5;

                this.sourcePort = htons(sourcePort);
                this.destPort = htons(destPort);
                sequence = htonl(seq);
                acknowledge = htonl(ack);
                
                nextHeaderFlags = htons((UInt16)(
                    (headerSize << 12) |
                    (acknowledge != 0 ? 0x10 : 0)));

                window = 0xffff;
                checksum = 0;
                urgent = 0;
            }
        }

        UInt16 tcpConnectionId(IPEndPoint src, IPEndPoint dst)
        {
            byte[] addr1 = src.Address.GetAddressBytes();
            byte[] port1 = src.Port.GetBytes();
            byte[] addr2 = dst.Address.GetAddressBytes();
            byte[] port2 = dst.Port.GetBytes();

            byte[] data = new byte[addr1.Length + port1.Length + addr2.Length + port2.Length];

            addr1.CopyTo(data, 0);
            port1.CopyTo(data, addr1.Length);
            addr2.CopyTo(data, addr1.Length + port1.Length);
            port2.CopyTo(data, addr1.Length + port1.Length + addr2.Length);

            return Crc16.ComputeChecksum(data);
        }
    }
    public static class Crc16
    {
        const ushort polynomial = 0xA001;
        static readonly ushort[] table = new ushort[256];

        public static ushort ComputeChecksum(byte[] bytes)
        {
            ushort crc = 0;
            for (int i = 0; i < bytes.Length; ++i)
            {
                byte index = (byte)(crc ^ bytes[i]);
                crc = (ushort)((crc >> 8) ^ table[index]);
            }
            return crc;
        }

        static Crc16()
        {
            ushort value;
            ushort temp;
            for (ushort i = 0; i < table.Length; ++i)
            {
                value = 0;
                temp = i;
                for (byte j = 0; j < 8; ++j)
                {
                    if (((value ^ temp) & 0x0001) != 0)
                    {
                        value = (ushort)((value >> 1) ^ polynomial);
                    }
                    else
                    {
                        value >>= 1;
                    }
                    temp >>= 1;
                }
                table[i] = value;
            }
        }
    }
}
