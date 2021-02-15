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
        private const UInt32 magic2 = 0xb49a704d;

        [StructLayout(LayoutKind.Explicit, Size = 0x1B, CharSet = CharSet.Ansi)]
        public struct FoscamRequest
        {
            [FieldOffset(0x00)] public UInt32 magic;
            [FieldOffset(0x04)] public UInt32 _uint32_04; // 0
            [FieldOffset(0x08)] public UInt32 _uint32_08; // 0
            [FieldOffset(0x0C)] public UInt32 _uint32_0C; // 4
            [FieldOffset(0x10)] public UInt32 _uint32_10; // 4
            [FieldOffset(0x14)] public UInt32 _uint32_14; // 0
            [FieldOffset(0x18)] public UInt16 _uint16_18; // 0
            [FieldOffset(0x1A)] public byte _byte_1A; // 1
        

            public FoscamRequest(int init)
            {
                magic = NetworkUtils.HostToNetworkOrder32(Foscam.magic);
                _uint32_04 = NetworkUtils.HostToNetworkOrder32(0);
                _uint32_08 = NetworkUtils.HostToNetworkOrder32(0);
                _uint32_0C = NetworkUtils.HostToNetworkOrder32(4);
                _uint32_10 = NetworkUtils.HostToNetworkOrder32(4);
                _uint32_14 = NetworkUtils.HostToNetworkOrder32(0);
                _uint16_18 = NetworkUtils.HostToNetworkOrder16(0);
                _byte_1A = 1;
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x05, CharSet = CharSet.Ansi)]
        public struct FoscamRequest2
        {
            [FieldOffset(0x00)] public UInt32 magic;
            [FieldOffset(0x04)] public byte _byte_04; // 0

            public FoscamRequest2(int init)
            {
                magic = NetworkUtils.HostToNetworkOrder32(Foscam.magic2);
                _byte_04 = 0;
            }
        }

        public override int color
        {
            get
            {
                return Color.Red.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Foscam";
            }
        }
        public Foscam()
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
            FoscamRequest req;

            req = new FoscamRequest(1);

            return req.GetBytes();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            viewer.deviceFound(name, 1, from.Address, "Unknown", "Unknown");
        }

    }
}

