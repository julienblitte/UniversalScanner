using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class Ubiquiti : ScanEngine
    {
        protected readonly string multicastIP = "233.89.188.1";
        protected const int port = 10001;

        protected readonly UInt32 requestVersion = 1;
        protected readonly UInt16 anwserMagic = 0x0206;

        private enum UbiquitiValue
        {
            typeNull = 0x0000,
            macAddress1 = 0x0001, // binary: 4 bytes
            macIPv4 = 0x0002,     // binary: 10 bytes
            firmware = 0x0003,    // string
            uptime = 0x000a,      // binary: in sec, big endian
            brand = 0x000b,       // string
            model1 = 0x000c,      // string
            firmware_version = 0x0016, // string
            model2 = 0x0015,      // string
            bool_0x17 = 0x0017,
            bool_0x18 = 0x0018,
            bool_0x19 = 0x0019,
            bool_0x1a = 0x001a,
            macAddress2 = 0x0013,  // binary: 4 bytes
            counter = 0x0012,     // incremented value
            hw_version = 0x001b,  // string
            binary_0x24 = 0x0024
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
                return "Ubiquiti";
            }
        }

        public Ubiquiti()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x04, CharSet = CharSet.Ansi)]
        public struct UbiquitiHeader
        {
            [FieldOffset(0x00)] public UInt16 magic;
            [FieldOffset(0x02)] public UInt16 packetSize;
        }

        public override void scan()
        {
#if DEBUG
            selfTest();
#endif
            sendMulticast(IPAddress.Parse(multicastIP), port);
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            UInt32 payload;
            payload = NetworkUtils.littleEndian32(requestVersion);

            return payload.GetBytes();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            UbiquitiHeader header;
            int headerSize;
            int position;
            IPAddress IPv4;
            byte[] mac;
            string macAddress;
            string model;

            headerSize = typeof(UbiquitiHeader).StructLayoutAttribute.Size;

            if (data.Length < headerSize)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Ubiquiti.reciever(): Invalid size packet recieved from {0}", from.ToString()));
                return;
            }

            header = data.GetStruct<UbiquitiHeader>();
            if (NetworkUtils.bigEndian16(header.magic) != anwserMagic)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Ubiquiti.reciever(): Invalid magic value from {0}", from.ToString()));
                /* not enougth tested Ubiquiti answer to say it is always this magic, so disabling return for now */
                // return;
            }

            if (NetworkUtils.bigEndian16(header.packetSize) != data.Length - 4)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Ubiquiti.reciever(): Invalid packet size value (got value {0} while value {1} was expected) from {2}",
                                 NetworkUtils.bigEndian16(header.packetSize), data.Length - 4, from.ToString()));
                return;
            }

            position = headerSize;
            IPv4 = null;
            mac = null;
            model = "";

            while (position < data.Length)
            {
                UInt16 variable;
                byte[] value;

                variable = readNextValue(data, ref position, out value);
                switch (variable)
                {
                    case (byte)UbiquitiValue.typeNull:
                        Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: Ubiquiti.reciever(): Invalid packet, variable type null");
                        return;

                    case (byte)UbiquitiValue.macAddress1: // binary: 4 bytes
                    case (byte)UbiquitiValue.macAddress2: // binary: 4 bytes
                        if (value.Length != 6)
                        {
                            Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Ubiquiti.reciever(): invalid size of variable 0x{0:X4} (expected={1}, found={2})",
                                            (UInt16)variable, 6, value.Length));
                            break;
                        }
                        if (mac == null)
                        {
                            mac = value;
                        }
                        break;

                    case (byte)UbiquitiValue.macIPv4: // binary: 10 bytes
                        if (value.Length != 10)
                        {
                            Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: Ubiquiti.reciever(): invalid size of variable 0x{0:X4} (expected={1}, found={2})",
                                            (UInt16)variable, 10, value.Length));
                            break;
                        }
                        if (mac == null)
                        {
                            mac = new byte[6];
                            Array.Copy(value, 0, mac, 0, 6);
                        }
                        if (IPv4 == null)
                        {
                            var IPv4Bytes = new byte[4];
                            Array.Copy(value, 6, IPv4Bytes, 0, 4);
                            IPv4 = new IPAddress(IPv4Bytes);
                        }
                        break;

                    case (byte)UbiquitiValue.model1: // string
                    case (byte)UbiquitiValue.model2: // string
                        if (model == "")
                        {
                            model = Encoding.UTF8.GetString(value);
                        }
                        break;
                }
            }

            if (IPv4 == null)
            {
                IPv4 = from.Address;
            }
            if (mac != null && IPv4 != null)
            {
                macAddress = String.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                if (model == "")
                {
                    model = "unknown";
                }

                viewer.deviceFound(name, 1, IPv4, model, macAddress);
            }
        }

        private UInt16 readNextValue(byte[] data, ref int position, out byte[] value)
        {
            UInt16 vtype;
            byte size;

            if (position + 3 >= data.Length)
            {
                value = null;
                return 0x0000;
            }
            vtype = data[position];
            position++;
            vtype |= (UInt16)(data[position] << 8);
            position++;

            size = data[position];
            position++;

            if (position + size > data.Length)
            {
                value = null;
                return 00;
            }
            value = new byte[size];
            Array.Copy(data, position, value, 0, size);
            position += size;

            return vtype;
        }
    }
}
