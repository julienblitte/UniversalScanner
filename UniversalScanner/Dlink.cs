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
    class Dlink : ScanEngine
    {
        private const int port = 62976;
        private const UInt16 magic = 0xFDFD;
        private UInt16 sessionId;

        [StructLayout(LayoutKind.Explicit, Size = 0x06, CharSet = CharSet.Ansi)]
        public struct MacAddress
        {
            [FieldOffset(0x00)] public byte byte00;
            [FieldOffset(0x01)] public byte byte01;
            [FieldOffset(0x02)] public byte byte02;
            [FieldOffset(0x03)] public byte byte03;
            [FieldOffset(0x04)] public byte byte04;
            [FieldOffset(0x05)] public byte byte05;
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x18, CharSet = CharSet.Ansi)]
        public struct DLinkRequest
        {
            [FieldOffset(0x00)] public UInt16 magic;
            [FieldOffset(0x02)] public UInt16 session;
            [FieldOffset(0x04)] public UInt16 _uint32_04;
            [FieldOffset(0x06)] public MacAddress destination;
            [FieldOffset(0x0C)] public UInt16 _uint32_0C;
            [FieldOffset(0x0E)] public UInt16 _uint32_0E;
            [FieldOffset(0x10)] public UInt16 _uint32_10;
            [FieldOffset(0x12)] public UInt16 _uint32_12;
            [FieldOffset(0x14)] public UInt16 _uint32_14;

            public DLinkRequest(UInt16 sessionId)
            {
                magic = Dlink.magic;
                session = NetworkUtils.HostToNetworkOrder16(sessionId);
                _uint32_04 = NetworkUtils.HostToNetworkOrder16(0x00A1);
                destination = new MacAddress() { byte00 = 0xff, byte01 = 0xff, byte02 = 0xff, byte03 = 0xff, byte04 = 0xff, byte05 = 0xff };
                _uint32_0C = NetworkUtils.bigEndian16(0x0000);
                _uint32_0E = NetworkUtils.bigEndian16(0x0000);
                _uint32_10 = NetworkUtils.bigEndian16(0x0000);
                _uint32_12 = NetworkUtils.bigEndian16(0x0002);
                _uint32_14 = NetworkUtils.bigEndian16(0x0000);
            }
        }

        public override int color
        {
            get
            {
                return 0x002B8CA1;
            }
        }
        public override string name
        {
            get
            {
                return "Dlink";
            }
        }
        public Dlink()
        {
            sessionId = 0;
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
            DLinkRequest req;

            sessionId++;
            req = new DLinkRequest(sessionId);

            return req.GetBytes();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            viewer.deviceFound(name, 1, from.Address, "Unknown", "Unknown");
        }

    }
}

