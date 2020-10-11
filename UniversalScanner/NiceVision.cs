using System;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using JulienBlitte;

/*
 * @description: UniversalScanner discovery protocol
 */

namespace UniversalScanner
{
    class NiceVision : ScanEngine
    {
        private const int requestPort = 2007;
        private int answerPort;
        private UInt16 transactionId;

        private static readonly UInt32 magic = 0x4e494345; // 'NICE'
        private static readonly UInt32 payload = 0x01080000;

        [StructLayout(LayoutKind.Explicit, Size = 0x0C, CharSet = CharSet.Ansi)]
        public struct NiceVisionRequest
        {
            [FieldOffset(0x00)] public UInt32 magic;
            [FieldOffset(0x04)] public UInt16 transaction;
            [FieldOffset(0x06)] public UInt32 payload;
            [FieldOffset(0x0c)] public UInt16 answerPort;

            public NiceVisionRequest(UInt16 transactionId, UInt16 answerToPort)
            {
                magic = NetworkUtils.bigEndian32(NiceVision.magic);
                transaction = NetworkUtils.bigEndian16(transactionId);
                payload = NetworkUtils.bigEndian32(NiceVision.payload);
                answerPort = NetworkUtils.bigEndian16((UInt16)answerToPort);
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x06, CharSet = CharSet.Ansi)]
        public struct MacAddress
        {
            [FieldOffset(0x00)] public byte byte00;
            [FieldOffset(0x01)] public byte byte01;
            [FieldOffset(0x02)] public byte byte02;
            [FieldOffset(0x03)] public byte byte03;
            [FieldOffset(0x04)] public byte byte04;
            [FieldOffset(0x05)] public byte byte05;
        };

        [StructLayout(LayoutKind.Explicit, Size = 0x16, CharSet = CharSet.Ansi)]
        public struct String16Bytes
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
        };

        [StructLayout(LayoutKind.Explicit, Size = 0x5A, CharSet = CharSet.Ansi)]
        public struct NiceVisionAnswer
        {
            [FieldOffset(0x00)] public UInt32 magic;
            [FieldOffset(0x04)] public UInt16 transactionID1;
            [FieldOffset(0x06)] public byte _byte_06;
            [FieldOffset(0x07)] public byte _byte_07;
            [FieldOffset(0x08)] public byte _byte_08;
            [FieldOffset(0x09)] public byte _byte_09;
            [FieldOffset(0x0A)] public MacAddress mac;
            [FieldOffset(0x10)] public UInt32 ipv4;
            [FieldOffset(0x14)] public UInt32 mask;
            [FieldOffset(0x18)] public UInt32 gateway;
            [FieldOffset(0x1C)] public byte _byte_1C;
            [FieldOffset(0x1D)] public byte _byte_1D;
            [FieldOffset(0x1E)] public UInt16 version1;
            [FieldOffset(0x20)] public UInt16 version2;
            [FieldOffset(0x22)] public UInt16 version3;
            [FieldOffset(0x24)] public UInt16 version4;
            [FieldOffset(0x26)] public UInt32 _uint32_26;
            [FieldOffset(0x2A)] public UInt32 _uint32_2A;
            [FieldOffset(0x2E)] public UInt32 _uint32_2E;
            [FieldOffset(0x32)] public UInt32 _uint32_32;
            [FieldOffset(0x36)] public UInt32 _uint32_36;
            [FieldOffset(0x3A)] public UInt32 _uint32_3A;
            [FieldOffset(0x3E)] public UInt32 _uint32_3E;
            [FieldOffset(0x42)] public UInt32 _uint32_42;
            [FieldOffset(0x46)] public UInt32 _uint32_46;
            [FieldOffset(0x4A)] public String16Bytes name;
        }

        public override int color
        {
            get
            {
                return 0x0032948E;
            }
        }
        public override string name
        {
            get
            {
                return "NiceVision";
            }
        }
        public NiceVision()
        {
            transactionId = 0;

            listenUdpInterfaces();
            answerPort = listenUdpGlobal();
        }

        public override void scan()
        {
#if DEBUG
            selfTest();
#endif
            sendBroadcast(requestPort);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            NiceVisionRequest req;

            transactionId++;

            req = new NiceVisionRequest(transactionId, (UInt16)answerPort);
            return req.GetBytes();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string deviceModel, deviceSerial;
            IPAddress ip;
            NiceVisionAnswer answer;

            answer = data.GetStruct<NiceVisionAnswer>();

            deviceSerial = String.Format("{0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}", answer.mac.byte00, answer.mac.byte01, answer.mac.byte02,
                                            answer.mac.byte03, answer.mac.byte04, answer.mac.byte05);

            deviceModel = Encoding.UTF8.GetString(answer.name);
            ip = new IPAddress(answer.ipv4);

                viewer.deviceFound(name, 1, ip, deviceModel, deviceSerial);
        }

    }
}

