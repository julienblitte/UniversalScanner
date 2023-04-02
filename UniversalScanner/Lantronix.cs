using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Drawing;
using JulienBlitte;

/*
 * @description: UniversalScanner discovery protocol
 */

namespace UniversalScanner
{
    class Lantronix : ScanEngine
    {
        private const int port = 30718;
        private const byte messageTypeRequest = 0xf6;
        private const byte messageTypeReply = 0xf7;

        private enum protocolMagic : byte
        {
            vaubanOld = 0x13,
            vauban = 0x15
        };

        private readonly byte[] discover = { 0x00, 0x00, 0x00, messageTypeRequest };

        public override int color
        {
            get
            {
                return Color.DarkOrange.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Lantronix";
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

        [StructLayout(LayoutKind.Explicit, Size = 0x14, CharSet = CharSet.Ansi)]
        public struct VaubanPayload
        {
            [FieldOffset(0x00)] public UInt32 _uint32_04;
            [FieldOffset(0x04)] public UInt32 _uint32_08;
            [FieldOffset(0x08)] public byte modelMajor;
            [FieldOffset(0x09)] public byte modelMinor;
            [FieldOffset(0x0A)] public UInt16 version;
            [FieldOffset(0x0C)] public UInt32 gateway;
            [FieldOffset(0x10)] public UInt32 _uint32_14;
        }


        [StructLayout(LayoutKind.Explicit, Size = 0x14, CharSet = CharSet.Ansi)]
        public struct LantronixAnswerPayload
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
        }


        [StructLayout(LayoutKind.Explicit, Size = 0x1E, CharSet = CharSet.Ansi)]
        public struct LantronixAnswer
        {
            [FieldOffset(0x00)] public byte _byte_00;
            [FieldOffset(0x01)] public byte _byte_01;
            [FieldOffset(0x02)] public byte _byte_03;
            [FieldOffset(0x03)] public byte messageType;
            [FieldOffset(0x04)] public LantronixAnswerPayload payload;
            [FieldOffset(0x18)] public MacAddress mac;
        }

        public Lantronix()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
        }

        public override void scan()
        {
#if DEBUG
            selfTest();
            selfTest("Vauban.selftest", 1);
#endif
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return discover;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            LantronixAnswer answer;
            string mac;
            //VaubanPayload vauban;

            if (data.Length != typeof(LantronixAnswer).StructLayoutAttribute.Size)
            {
                return;
            }

            answer = data.GetStruct<LantronixAnswer>();

            if (answer.messageType != messageTypeReply)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, "Warning: Lantroinux.reciever(): Packet with wrong header.");
                return;
            }

            mac = String.Format("{0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}", answer.mac.byte00, answer.mac.byte01, answer.mac.byte02,
                answer.mac.byte03, answer.mac.byte04, answer.mac.byte05);

            // trying vauban
            if (answer._byte_03 == (byte)protocolMagic.vauban)
            {
                var payload = answer.payload.GetBytes();
                var vauban = payload.GetStruct<VaubanPayload>();

                if (vauban.modelMajor == 02 && vauban.modelMinor < 10)
                {
                    string model;

                    switch (vauban.modelMajor)
                    {
                        case 02:
                            model = "Verso+";
                            break;
                        default:
                            model = "unknown";
                            break;
                    }

                    switch (vauban.modelMinor)
                    {
                        case 02:
                            model += " 2";
                            break;
                        case 04:
                            model += " 4";
                            break;
                    }

                    viewer.deviceFound("Vauban", 1, from.Address, model, mac);

                    return;
                }
            }
            else if (answer._byte_03 == (byte)protocolMagic.vaubanOld)
            {
                viewer.deviceFound("Vauban", 1, from.Address, "unknown", mac);

                return;
            }

            viewer.deviceFound(name, 1, from.Address, "unknown", mac);
        }

    }
}

