using JulienBlitte;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

namespace UniversalScanner
{
    class CyberPower : ScanEngine
    {
        private const int port = 53566;

        private readonly byte requestMagic = 0x11;
        private readonly byte answerMagic = 0x51;

        public override int color
        {
            get
            {
                return Color.DarkOrange.ToArgb();
            }
        }

        public override UInt16[] getUsedPort()
        {
            return new UInt16[] { port };
        }

        public override string name
        {
            get
            {
                return "CyberPower";
            }
        }
        public CyberPower()
        {

        }
        public override void listen()
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

            
            result = new byte[3];  // first byte is magic

            result[1] = 0x01;      // this value must be not null;
            result[1] = result[2]; // make sure two last bytes are identical

            result[0] = requestMagic;

            return result;
        }

        public byte read8(byte[] data, ref int position)
        {
            if (position > data.Length - 1)
            {
                throw new ArgumentOutOfRangeException(); 
            }

            return data[position++];
        }

        public UInt32 read32(byte[] data, ref int position)
        {
            UInt32 result;

            if (position + 3 > data.Length - 1)
            {
                throw new ArgumentOutOfRangeException();
            }

            result = (((uint)data[position] << 24)
                | ((uint)data[position + 1] << 16)
                | ((uint)(data[position + 2] << 8)
                | (uint)data[position + 3]));

            position += 4;

            return result;
        }

        public PhysicalAddress readMAC(byte[] data, ref int position)
        {
            byte[] addressBytes;

            if (position + 5 > data.Length - 1)
            {
                throw new ArgumentOutOfRangeException();
            }

            addressBytes = new byte[6];
            Array.Copy(data, position, addressBytes, 0, 6);

            position += 6;

            return new PhysicalAddress(addressBytes);
        }


        public string readString(byte[] data, ref int position)
        {
            byte len;
            string result;

            if (position > data.Length - 1)
            {
                throw new ArgumentOutOfRangeException();
            }

            len = data[position++];

            if (position + len -1 > data.Length - 1)
            {
                throw new ArgumentOutOfRangeException();
            }

            result = Encoding.UTF8.GetString(data, position, len);

            position += len;

            return result;

        }

        public void xor(ref byte[] data, byte key, int start, int end)
        {
            if (start < 0 || end < 0 || start > end)
            {
                throw new ArgumentException();
            }

            if (start > data.Length - 1 || end > data.Length -1)
            {
                throw new ArgumentOutOfRangeException();
            }

            for(int i=start; i <= end; i++)
            {
                data[i] ^= key;
            }
        }

        public void xor(ref byte[] data, byte key)
        {
            xor(ref data, key, 0, data.Length);
        }


        public override void reciever(IPEndPoint from, byte[] data)
        {
            string deviceName, deviceLocation, username;
            int position;

            IPAddress ip;

            byte magic, key;
            string hash;
            byte _byte_1, _byte_2, _byte_3;
            UInt32 _uint32_1;
            UInt32 uptime1, uptime2, ip_int, mask, gw, version;

            PhysicalAddress mac;
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
            position = 0;

            magic = read8(data, ref position);

            if (magic != answerMagic)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: CyberPower.reciever(): Invalid magic field: {0}", magic));
            }
            key = read8(data, ref position);
            hash = readString(data, ref position);
            _uint32_1 = read32(data, ref position);
            uptime1 = read32(data, ref position);

            xor(ref data, key, position, data.Length - 1); // uncipher

            _byte_1 = read8(data, ref position);
            mac = readMAC(data, ref position);
            _byte_2 = read8(data, ref position);
            ip_int = read32(data, ref position);
            mask = read32(data, ref position);
            gw = read32(data, ref position);
            version = read32(data, ref position);
            deviceName = readString(data, ref position);
            deviceLocation = readString(data, ref position);
            username = readString(data, ref position);
            _byte_3 = read8(data, ref position);
            uptime2 = read32(data, ref position);

            ip = new IPAddress(NetworkUtils.NetworkToHostOrder32(ip_int));

            // TODO: replace deviceName by devideModel and try to detect it
            // TODO: known type values are 2=ATS / 3=BM / 4=Data Logger / 1=PDU / 0=UPS

            viewer.deviceFound(name, 1, ip, deviceName, mac.ToString());
        }

    }
}

