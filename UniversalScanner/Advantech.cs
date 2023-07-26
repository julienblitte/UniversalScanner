using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.Drawing;
using JulienBlitte;

/*
 * @description: Advantech discovery protocol
 */

namespace UniversalScanner
{
    class Advantech : ScanEngine
    {
        private const int port = 5048;
        private const UInt32 magic = 0x4144414D;

        private readonly byte[] request = { /* request type: ProductType */
            0x4d, 0x41, 0x44, 0x41, 0x00, 0x00, 0x00, 0x83, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        public enum MessageType : byte
        {
            NetAddress = 0x10,  // IP configuration
            DeviceName = 0x00,  // product name
            ProductType = 0x20	// product information
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

            public override string ToString()
            {
                return String.Format("{0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}", byte00, byte01, byte02, byte03, byte04, byte05);
            }
        };

        [StructLayout(LayoutKind.Explicit, Size = 0x38, CharSet = CharSet.Ansi)]
        public struct AdvantechHeader
        {
            [FieldOffset(0x00)] public UInt32 headerMagic;     // 0x4144414D  little endian
            [FieldOffset(0x04)] public UInt32 _reserved_04;    // big endian! always 83
            [FieldOffset(0x08)] public UInt16 versionMajor;    // little endian
            [FieldOffset(0x0A)] public UInt16 versionMinor;    // little endian
            [FieldOffset(0x0C)] public byte _padding_0C;
            [FieldOffset(0x0D)] public MacAddress mac;
            [FieldOffset(0x13)] public byte _padding_13;
            [FieldOffset(0x14)] public UInt32 _uint32_14;
            [FieldOffset(0x18)] public UInt32 _uint32_18;
            [FieldOffset(0x1C)] public UInt32 _uint32_1C;
            [FieldOffset(0x20)] public UInt32 _uint32_20;
            [FieldOffset(0x24)] public UInt32 _uint32_24;
            [FieldOffset(0x28)] public UInt32 _uint32_28;
            [FieldOffset(0x2C)] public UInt32 _uint32_2C;
            [FieldOffset(0x30)] public UInt32 _uint32_30;
            [FieldOffset(0x34)] public byte isReply;        // 0x80 if reply, 0x00 otherwise
            [FieldOffset(0x35)] public byte messageType;    // 0x10: for IP address info, 0x00 for device name, 0x20 for device type
            [FieldOffset(0x36)] public UInt16 nextPartSize; // Big endian! looks to be wrong for 0x20 message reply! 
        }

        public override int color
        {
            get
            {
                return Color.DarkCyan.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "Advantech";
            }
        }
        public Advantech()
        {
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
            return request;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            if (data.Length >= typeof(AdvantechHeader).StructLayoutAttribute.Size + 0x32)
            {

                if (data.Length >= typeof(AdvantechHeader).StructLayoutAttribute.Size)
                {
                    AdvantechHeader advantechAnswer;
                    string deviceSerial, deviceModel;
                    byte[] deviceModelBinary;
                    int dataIndex, dataSize;

                    advantechAnswer = data.GetStruct<AdvantechHeader>();
                    deviceSerial = advantechAnswer.mac.ToString();
                    deviceModel = "Unknown";

                    if (advantechAnswer.messageType == (byte)MessageType.ProductType &&
                        data.Length >= typeof(AdvantechHeader).StructLayoutAttribute.Size + 0x32)
                    {
                        dataIndex = typeof(AdvantechHeader).StructLayoutAttribute.Size + 0x32;
                        dataSize = data.Length - dataIndex;

                        deviceModelBinary = new byte[dataSize];
                        try
                        {
                            Array.Copy(data, dataIndex, deviceModelBinary, 0, dataSize);
                            deviceModel = Encoding.UTF8.GetString(deviceModelBinary);
                        }
                        catch (Exception)
                        {
                            deviceModel = "Unknown";
                        }
                    }
                    viewer.deviceFound(name, 1, from.Address, deviceModel, deviceSerial);
                }
            }
        }

    }
}

