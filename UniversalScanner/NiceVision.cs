using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.Drawing;

/*
 * @description: UniversalScanner discovery protocol
 */

namespace UniversalScanner
{
    class NiceVision : ScanEngine
    {
        private const int requestPort = 2007;
        private int answerPort;

        private readonly UInt32 magic = 0x4e494345; // 'NICE'
        private readonly UInt32 payload = 0x01080000;

        [StructLayout(LayoutKind.Explicit, Size = 12, CharSet = CharSet.Ansi)]
        public struct NiceVisionRequest
        {
            [FieldOffset(0)] public UInt32 magic;
            [FieldOffset(4)] public UInt16 transactionID;
            [FieldOffset(6)] public UInt32 payload;
            [FieldOffset(10)] public UInt16 answerPort;
        }

        [StructLayout(LayoutKind.Explicit, Size = 6, CharSet = CharSet.Ansi)]
        public struct MacAddress
        {
            [FieldOffset(0)] public byte byte00;
            [FieldOffset(1)] public byte byte01;
            [FieldOffset(2)] public byte byte02;
            [FieldOffset(3)] public byte byte03;
            [FieldOffset(4)] public byte byte04;
            [FieldOffset(5)] public byte byte05;
        };

        [StructLayout(LayoutKind.Explicit, Size = 10, CharSet = CharSet.Ansi)]
        public struct DeviceName
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
        };

        [StructLayout(LayoutKind.Explicit, Size = 12, CharSet = CharSet.Ansi)]
        public struct NiceVisionAnswer
        {
            [FieldOffset(0)] public UInt32 magic;
            [FieldOffset(4)] public UInt16 transactionID1;
            [FieldOffset(6)] public byte _value_06;
            [FieldOffset(7)] public byte _value_07;
            [FieldOffset(8)] public byte _value_08;
            [FieldOffset(9)] public byte _value_09;
            [FieldOffset(10)] public MacAddress mac;
            [FieldOffset(16)] public UInt32 ipv4;
            [FieldOffset(20)] public UInt32 mask;
            [FieldOffset(24)] public UInt32 gateway;
            [FieldOffset(28)] public byte _value_1C;
            [FieldOffset(29)] public byte _value_1D;
            [FieldOffset(30)] public UInt16 version1;
            [FieldOffset(32)] public UInt16 version2;
            [FieldOffset(34)] public UInt16 version3;
            [FieldOffset(36)] public UInt16 version4;
            [FieldOffset(38)] public UInt32 padding_28;
            [FieldOffset(42)] public UInt32 padding_2C;
            [FieldOffset(46)] public UInt32 padding_30;
            [FieldOffset(50)] public UInt32 padding_34;
            [FieldOffset(54)] public UInt32 padding_38;
            [FieldOffset(58)] public UInt32 padding_3C;
            [FieldOffset(62)] public UInt32 padding_40;
            [FieldOffset(66)] public UInt32 padding_44;
            [FieldOffset(70)] public byte _value_48;
            [FieldOffset(71)] public byte _value_49;
            [FieldOffset(72)] public byte _value_4A;
            [FieldOffset(73)] public byte _value_4B;
            [FieldOffset(74)] public DeviceName name;
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

            req = new NiceVisionRequest() { magic = NetworkUtils.htonl(magic), transactionID = NetworkUtils.htons(1),
                payload = NetworkUtils.htonl(payload), answerPort = NetworkUtils.htons((UInt16)answerPort) };
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

