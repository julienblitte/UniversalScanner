using System;
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
    class GigEVision : ScanEngine
    {
        private const int port = 3956;

        private UInt16 requestCounter;

        [StructLayout(LayoutKind.Explicit, Size = 0x08, CharSet = CharSet.Ansi)]
        public struct GigEVisionRequest
        {
            [FieldOffset(0x00)] public byte messageType;
            [FieldOffset(0x01)] public byte flags;
            [FieldOffset(0x02)] public UInt16 command;
            [FieldOffset(0x04)] public UInt16 payloadLen;
            [FieldOffset(0x06)] public UInt16 requestId;

            public GigEVisionRequest(UInt16 requestCounter)
            {
                messageType = 0x42;
                flags = 0x11;
                command = NetworkUtils.HostToNetworkOrder16(0x0002);
                payloadLen = 0;
                requestId = requestCounter;
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
        }

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

        [StructLayout(LayoutKind.Explicit, Size = 0x30, CharSet = CharSet.Ansi)]
        public struct String48bytes
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
            [FieldOffset(0x20)] public byte byte20;
            [FieldOffset(0x21)] public byte byte21;
            [FieldOffset(0x22)] public byte byte22;
            [FieldOffset(0x23)] public byte byte23;
            [FieldOffset(0x24)] public byte byte24;
            [FieldOffset(0x25)] public byte byte25;
            [FieldOffset(0x26)] public byte byte26;
            [FieldOffset(0x27)] public byte byte27;
            [FieldOffset(0x28)] public byte byte28;
            [FieldOffset(0x29)] public byte byte29;
            [FieldOffset(0x2A)] public byte byte2A;
            [FieldOffset(0x2B)] public byte byte2B;
            [FieldOffset(0x2C)] public byte byte2C;
            [FieldOffset(0x2D)] public byte byte2D;
            [FieldOffset(0x2E)] public byte byte2E;
            [FieldOffset(0x2F)] public byte byte2F;
        }


        [StructLayout(LayoutKind.Explicit, Size = 0x100, CharSet = CharSet.Ansi)]
        public struct GigEVisionAckn
        {
            [FieldOffset(0x00)] public UInt16 status;
            [FieldOffset(0x02)] public UInt16 ack;
            [FieldOffset(0x04)] public UInt16 payloadLen;
            [FieldOffset(0x06)] public UInt16 requestId;
            [FieldOffset(0x08)] public UInt16 plMajorVersion;
            [FieldOffset(0x0A)] public UInt16 plMinorVersion;
            [FieldOffset(0x0C)] public UInt32 plDeviceFlags;
            [FieldOffset(0x10)] public byte _byte_10;
            [FieldOffset(0x11)] public byte _byte_11;
            [FieldOffset(0x12)] public MacAddress plMacAddress;
            [FieldOffset(0x18)] public UInt32 plIPOptionsfFlags;
            [FieldOffset(0x1C)] public UInt32 plIPCurrentFlags;
            [FieldOffset(0x20)] public byte _byte_20;
            [FieldOffset(0x21)] public byte _byte_21;
            [FieldOffset(0x22)] public byte _byte_22;
            [FieldOffset(0x23)] public byte _byte_23;
            [FieldOffset(0x24)] public byte _byte_24;
            [FieldOffset(0x25)] public byte _byte_25;
            [FieldOffset(0x26)] public byte _byte_26;
            [FieldOffset(0x27)] public byte _byte_27;
            [FieldOffset(0x28)] public byte _byte_28;
            [FieldOffset(0x29)] public byte _byte_29;
            [FieldOffset(0x2A)] public byte _byte_2A;
            [FieldOffset(0x2B)] public byte _byte_2B;
            [FieldOffset(0x2C)] public UInt32 plIPCurrentAddr;
            [FieldOffset(0x30)] public byte _byte_30;
            [FieldOffset(0x31)] public byte _byte_31;
            [FieldOffset(0x32)] public byte _byte_32;
            [FieldOffset(0x33)] public byte _byte_33;
            [FieldOffset(0x34)] public byte _byte_34;
            [FieldOffset(0x35)] public byte _byte_35;
            [FieldOffset(0x36)] public byte _byte_36;
            [FieldOffset(0x37)] public byte _byte_37;
            [FieldOffset(0x38)] public byte _byte_38;
            [FieldOffset(0x39)] public byte _byte_39;
            [FieldOffset(0x3A)] public byte _byte_3A;
            [FieldOffset(0x3B)] public byte _byte_3B;
            [FieldOffset(0x3C)] public UInt32 plIPCurrentMask;
            [FieldOffset(0x40)] public byte _byte_40;
            [FieldOffset(0x41)] public byte _byte_41;
            [FieldOffset(0x42)] public byte _byte_42;
            [FieldOffset(0x43)] public byte _byte_43;
            [FieldOffset(0x44)] public byte _byte_44;
            [FieldOffset(0x45)] public byte _byte_45;
            [FieldOffset(0x46)] public byte _byte_46;
            [FieldOffset(0x47)] public byte _byte_47;
            [FieldOffset(0x48)] public byte _byte_48;
            [FieldOffset(0x49)] public byte _byte_49;
            [FieldOffset(0x4A)] public byte _byte_4A;
            [FieldOffset(0x4B)] public byte _byte_4B;
            [FieldOffset(0x4C)] public UInt32 plIPCurrentGateway;
            [FieldOffset(0x50)] public String32bytes plManufacturer;
            [FieldOffset(0x70)] public String32bytes plModel;
            [FieldOffset(0x90)] public String32bytes plVersion;
            [FieldOffset(0xB0)] public String48bytes plSpecificInfo;
            [FieldOffset(0xE0)] public String16bytes plSerialNumber;
            [FieldOffset(0xF0)] public String16bytes plUsername;
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
                return "GigEVision";
            }
        }
        public GigEVision()
        {
            requestCounter = 0;

            //listenUdpGlobal(port);
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
            GigEVisionRequest request;

            requestCounter++;
            request = new GigEVisionRequest(requestCounter);

            return request.GetBytes();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            GigEVisionAckn answer;
            UInt32 version;
            string macAddress;
            IPAddress ipv4;

            string model;
            string vendor;
            string serial;

            if (data.Length != typeof(GigEVisionAckn).StructLayoutAttribute.Size)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: GigEVision.reciever(): Invalid size packet recieved from {0}", from.ToString()));
                return;
            }

            answer = data.GetStruct<GigEVisionAckn>();

            if (NetworkUtils.NetworkToHostOrder16(answer.payloadLen) != data.Length - 8)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: GigEVision.reciever(): Invalid size payload length value (got value {0} while value {1} was expected) recieved from {2}",
                    NetworkUtils.NetworkToHostOrder16(answer.payloadLen), data.Length - 8, from.ToString()));
                return;
            }

            version = ((UInt32)NetworkUtils.NetworkToHostOrder16(answer.plMajorVersion)) << 16 |
                ((UInt32)NetworkUtils.NetworkToHostOrder16(answer.plMinorVersion));

            if (version != 0x00010002)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: GigEVision.reciever(): Invalid packet version (got value 0x{0:X8} while value 0x{1:X8} was expected) recieved from {2}",
                    version, 0x00010002, from.ToString()));
            }


            if (answer.plIPCurrentAddr != 0)
            {
                ipv4 = new IPAddress((long)answer.plIPCurrentAddr);
            }
            else
            {
                ipv4 = from.Address;
            }

            macAddress = String.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                answer.plMacAddress.byte00, answer.plMacAddress.byte01, answer.plMacAddress.byte02,
                answer.plMacAddress.byte03, answer.plMacAddress.byte04, answer.plMacAddress.byte05);
            serial = Encoding.UTF8.GetString(answer.plSerialNumber);
            if (serial == "")
            {
                serial = macAddress;
            }

            vendor = Encoding.UTF8.GetString(answer.plManufacturer);
            if (vendor == "")
            {
                vendor = name;
            }

            model = Encoding.UTF8.GetString(answer.plModel);
            if (model == "")
            {
                model = Encoding.UTF8.GetString(answer.plUsername);
            }

            viewer.deviceFound(vendor, 0, ipv4, model, serial);
        }

    }
}

