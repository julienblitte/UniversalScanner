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
    class Lantronix : ScanEngine
    {
        private const int port = 30718;
        private const UInt32 requestMagic = 0x000000f6;
        private const UInt32 answerMagic = 0x000000f7;

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

        [StructLayout(LayoutKind.Explicit, Size = 0x1E, CharSet = CharSet.Ansi)]
        public struct LantronixAnswer
        {
            [FieldOffset(0x00)] public UInt32 magic;
            [FieldOffset(0x04)] public byte _byte_04;
            [FieldOffset(0x05)] public byte _byte_05;
            [FieldOffset(0x06)] public byte _byte_06;
            [FieldOffset(0x07)] public byte _byte_07;
            [FieldOffset(0x08)] public byte _byte_08;
            [FieldOffset(0x09)] public byte _byte_09;
            [FieldOffset(0x0A)] public byte _byte_0A;
            [FieldOffset(0x0B)] public byte _byte_0B;
            [FieldOffset(0x0C)] public byte _byte_0C;
            [FieldOffset(0x0D)] public byte _byte_0D;
            [FieldOffset(0x0E)] public byte _byte_0E;
            [FieldOffset(0x0F)] public byte _byte_0F;
            [FieldOffset(0x10)] public byte _byte_10;
            [FieldOffset(0x11)] public byte _byte_11;
            [FieldOffset(0x12)] public byte _byte_12;
            [FieldOffset(0x13)] public byte _byte_13;
            [FieldOffset(0x14)] public byte _byte_14;
            [FieldOffset(0x15)] public byte _byte_15;
            [FieldOffset(0x16)] public byte _byte_16;
            [FieldOffset(0x17)] public byte _byte_17;

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
#endif
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            byte[] result;
            UInt32 magic;

            magic = NetworkUtils.bigEndian32(requestMagic);
            result = new byte[4];
            result[0] = (byte)(magic << 24);
            result[1] = (byte)(magic << 16);
            result[2] = (byte)(magic << 8);
            result[3] = (byte)magic;

            return result;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            LantronixAnswer answer;
            string deviceSerial;

            if (data.Length != typeof(LantronixAnswer).StructLayoutAttribute.Size)
            {
                return;
            }

            answer = data.GetStruct<LantronixAnswer>();

            if (NetworkUtils.bigEndian32(answer.magic) != answerMagic)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, "Warning: Lantroinux.reciever(): Packet with wrong header.");
                return;
            }

            deviceSerial = String.Format("{0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}", answer.mac.byte00, answer.mac.byte01, answer.mac.byte02,
                            answer.mac.byte03, answer.mac.byte04, answer.mac.byte05);

            viewer.deviceFound(name, 1, from.Address, "unknown", deviceSerial);
        }

    }
}

