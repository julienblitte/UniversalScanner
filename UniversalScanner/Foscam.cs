using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.Drawing;
using JulienBlitte;

/*
 * @description: UniversalScanner discovery protocol
 */

namespace UniversalScanner
{
    class Foscam : ScanEngine
    {
        private const int port = 10000;
        private const UInt32 magic = 0x4d4f5f49;

        [StructLayout(LayoutKind.Explicit, Size = 0x08, CharSet = CharSet.Ansi)]
        public struct FoscamCipherKey
        {
            [FieldOffset(0x00)] public byte byte00;
            [FieldOffset(0x01)] public byte byte01;
            [FieldOffset(0x02)] public byte byte02;
            [FieldOffset(0x03)] public byte byte03;
            [FieldOffset(0x04)] public byte byte04;
            [FieldOffset(0x05)] public byte byte05;
            [FieldOffset(0x06)] public byte byte06;
            [FieldOffset(0x07)] public byte byte07;
        }


        [StructLayout(LayoutKind.Explicit, Size = 0x17, CharSet = CharSet.Ansi)]
        public struct FoscamHeader
        {
            [FieldOffset(0x00)] public UInt32 magic;
            [FieldOffset(0x04)] public UInt16 requestType;
            [FieldOffset(0x06)] public byte cipheredXor;
            [FieldOffset(0x07)] public FoscamCipherKey cipherKey;
            [FieldOffset(0x0F)] public byte packetSize;
            [FieldOffset(0x10)] public byte byte10;
            [FieldOffset(0x11)] public byte byte11;
            [FieldOffset(0x12)] public byte byte12;
            [FieldOffset(0x13)] public byte byte13;
            [FieldOffset(0x14)] public byte byte14;
            [FieldOffset(0x15)] public byte byte15;
            [FieldOffset(0x16)] public byte byte16;

            public FoscamHeader(byte size, byte requestType = 0)
            {
                magic = NetworkUtils.HostToNetworkOrder32(Foscam.magic);
                packetSize = size;
                cipheredXor = 0;
                cipherKey = new FoscamCipherKey();
                byte10 = byte11 = byte12 = byte13 = byte14 = byte15 = byte16 = 0;

                this.requestType = requestType;
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x1B, CharSet = CharSet.Ansi)]
        public struct FoscamRequest
        {
            [FieldOffset(0x00)] public FoscamHeader header;
            [FieldOffset(0x17)] public UInt32 value; // 1

            public FoscamRequest(int init)
            {
                header = new FoscamHeader(4);
                value = NetworkUtils.HostToNetworkOrder32(1);
            }
        }


        [StructLayout(LayoutKind.Explicit, Size = 0x0D, CharSet = CharSet.Ansi)]
        public struct String13bytes
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
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x15, CharSet = CharSet.Ansi)]
        public struct String21bytes
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
        }


        [StructLayout(LayoutKind.Explicit, Size = 0x57, CharSet = CharSet.Ansi)]
        public struct FoscamAnwser
        {
            [FieldOffset(0x00)] public FoscamHeader header; // 0x17
            [FieldOffset(0x17)] public String13bytes serial; // 0x0D
            [FieldOffset(0x24)] public String21bytes name; // 0x15
            [FieldOffset(0x39)] public UInt32 ip;
            [FieldOffset(0x3D)] public UInt32 mask;
            [FieldOffset(0x41)] public UInt32 gateway;
            [FieldOffset(0x45)] public UInt32 dns;
            [FieldOffset(0x49)] public byte deviceType;
            [FieldOffset(0x4A)] public byte byte50;
            [FieldOffset(0x4B)] public byte byte51;
            [FieldOffset(0x4C)] public byte byte52;
            [FieldOffset(0x4D)] public UInt32 fimwareVersion;
            [FieldOffset(0x51)] public UInt32 webVersion;
            [FieldOffset(0x55)] public UInt16 webPort;
        }

        public override string name
        {
            get
            {
                return "Foscam";
            }
        }
        public override UInt16[] getUsedPort()
        {
            return new UInt16[] { port };
        }

        public override int color
        {
            get
            {
                return Color.Red.ToArgb();
            }
        }

        public Foscam()
        {

        }
        public override void listen()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
        }

        public override void scan()
        {
#if DEBUG
            selfTest("foscam.selftest");
            selfTest("foscam_cipher.selftest");
#endif
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            FoscamRequest req;

            req = new FoscamRequest(1);

            return req.GetBytes();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            FoscamAnwser answer;
            string deviceModel, deviceSerial;
            byte[] ipBytes;

            if (data.Length < typeof(FoscamAnwser).StructLayoutAttribute.Size)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Foscam.reciever(): Packet has wrong size = {0} (packet is too small)", data.Length));
                return;
            }

            answer = data.GetStruct<FoscamAnwser>();
            if (NetworkUtils.NetworkToHostOrder32(answer.header.magic) != magic)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Foscam.reciever(): Packet has wrong header."));
                return;
            }

            // data is ciphered
            if (answer.header.cipheredXor != 0)
            {
                byte[] cipherKey;
                int offset, len;

                cipherKey = answer.header.cipherKey.GetBytes();
                offset = answer.header.GetType().StructLayoutAttribute.Size;
                len = data.Length - offset;

                for(int i=0; i < len; i++)
                {
                    data[i + offset] ^= cipherKey[i % 8];
                }

                answer = data.GetStruct<FoscamAnwser>();
                answer.header.cipheredXor = 0;
            }

            ipBytes = new byte[4];
            ipBytes[3] = (byte)(answer.ip >> 24);
            ipBytes[2] = (byte)(answer.ip >> 16);
            ipBytes[1] = (byte)(answer.ip >> 8);
            ipBytes[0] = (byte)(answer.ip >> 0);

            deviceSerial = Encoding.UTF8.GetString(answer.serial);
            deviceModel = "Type " + answer.deviceType;

            viewer.deviceFound(name, 1, new IPAddress(ipBytes), deviceModel, deviceSerial);
        }

    }
}

