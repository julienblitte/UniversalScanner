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
    class Vstarcam : ScanEngine
    {
        private const int port = 8600;

        private readonly UInt32 requestMagic = 0x44480101;
        private readonly UInt32 answerMagic = 0x44480108;

        [StructLayout(LayoutKind.Explicit, Size = 0x10, CharSet = CharSet.Ansi)]
        public struct String16bytes
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
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x20, CharSet = CharSet.Ansi)]
        public struct String32bytes
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
            [FieldOffset(0x15)] public byte byte15;
            [FieldOffset(0x16)] public byte byte16;
            [FieldOffset(0x17)] public byte byte17;
            [FieldOffset(0x18)] public byte byte18;
            [FieldOffset(0x19)] public byte byte19;
            [FieldOffset(0x1A)] public byte byte1A;
            [FieldOffset(0x1B)] public byte byte1B;
            [FieldOffset(0x1C)] public byte byte1C;
            [FieldOffset(0x1D)] public byte byte1D;
            [FieldOffset(0x1E)] public byte byte1E;
            [FieldOffset(0x1F)] public byte byte1F;
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x0C, CharSet = CharSet.Ansi)]
        public struct MacAddress
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
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x100, CharSet = CharSet.Ansi)]
        public struct VSCAnswerHeader
        {
            [FieldOffset(0x00)] public UInt32 answerMagic;
            [FieldOffset(0x04)] public String16bytes ip;
            [FieldOffset(0x14)] public String16bytes mask;
            [FieldOffset(0x24)] public String16bytes gateway;
            [FieldOffset(0x34)] public String16bytes dns1;
            [FieldOffset(0x44)] public String16bytes dns2;
            [FieldOffset(0x54)] public MacAddress mac;
            [FieldOffset(0x5A)] public UInt32 port;
            [FieldOffset(0x5C)] public String32bytes serial;
            [FieldOffset(0x7C)] public String32bytes name;
            [FieldOffset(0x9C)] public UInt32 _uint32_9C;
            [FieldOffset(0xA0)] public UInt32 _uint32_A0;
            [FieldOffset(0xA4)] public UInt32 _uint32_A4;
            [FieldOffset(0xA8)] public UInt32 _uint32_A8;
            [FieldOffset(0xAC)] public UInt32 _uint32_AC;
            [FieldOffset(0xB0)] public UInt32 _uint32_B0;
            [FieldOffset(0xB4)] public UInt32 _uint32_B4;
            [FieldOffset(0xB8)] public UInt32 _uint32_B8;
            [FieldOffset(0xBC)] public UInt32 _uint32_BC;
            [FieldOffset(0xC0)] public UInt32 _uint32_C0;
            [FieldOffset(0xC4)] public UInt32 _uint32_C4;
            [FieldOffset(0xC8)] public UInt32 _uint32_C8;
            [FieldOffset(0xCC)] public String32bytes firmware;
            [FieldOffset(0xEC)] public UInt32 _uint32_EC;
            [FieldOffset(0xF0)] public UInt32 _uint32_F0;
            [FieldOffset(0xF4)] public UInt32 _uint32_F4;
            [FieldOffset(0xF8)] public UInt32 _uint32_F8;
            [FieldOffset(0xFC)] public UInt32 _uint32_FC;
            // Cut second part from 0x100 to 0x210 
        }

        public override int color
        {
            get
            {
                return Color.DarkBlue.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "VStarcam";
            }
        }
        public Vstarcam()
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
            UInt32 magic;
            
            magic = NetworkUtils.HostToNetworkOrder32(requestMagic);

            return BitConverter.GetBytes(magic);
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            VSCAnswerHeader header;
            string deviceIP, deviceModel, deviceSerial;
            IPAddress ip;

            if (data.Length < typeof(VSCAnswerHeader).StructLayoutAttribute.Size)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: VStartCam.reciever(): Packet has wrong size = {0} (packet is too small)", data.Length));
                return;
            }

            header = data.GetStruct<VSCAnswerHeader>();

            if (NetworkUtils.NetworkToHostOrder32(header.answerMagic) != answerMagic)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: VStartCam.reciever(): Packet has wrong header."));
                return;
            }

            deviceIP = Encoding.UTF8.GetString(header.ip);
            deviceModel = Encoding.UTF8.GetString(header.name);
            deviceSerial = Encoding.UTF8.GetString(header.serial);

            if (IPAddress.TryParse(deviceIP, out ip))
            {
                viewer.deviceFound(name, 1, ip, deviceModel, deviceSerial);
            }
            else
            {
                viewer.deviceFound(name, 1, from.Address, deviceModel, deviceSerial);
            }
        }

    }
}

