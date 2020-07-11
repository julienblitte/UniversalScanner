using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    public static class NetworkUtils
    {
        public enum Endianness { BigEndian = 1, LittleEndian = 2 };

        // NetworkToHostOrder and HostToNetworkOrder from IPAddress are unsafe due type overload
        public static UInt16 NetworkToHostOrder16(UInt16 value)
        {
            return byteOrder16(value, Endianness.BigEndian);
        }
        public static UInt16 HostToNetworkOrder16(UInt16 value)
        {
            return byteOrder16(value, Endianness.BigEndian);
        }

        public static UInt32 NetworkToHostOrder32(UInt32 value)
        {
            return byteOrder32(value, Endianness.BigEndian);
        }
        public static UInt32 HostToNetworkOrder32(UInt32 value)
        {
            return byteOrder32(value, Endianness.BigEndian);
        }

        public static UInt64 NetworkToHostOrder64(UInt64 value)
        {
            return byteOrder64(value, Endianness.BigEndian);
        }
        public static UInt64 HostToNetworkOrder64(UInt64 value)
        {
            return byteOrder64(value, Endianness.BigEndian);
        }

        public static UInt16 littleEndian16(UInt16 value)
        {
            return byteOrder16(value, Endianness.LittleEndian);
        }

        public static UInt32 littleEndian32(UInt32 value)
        {
            return byteOrder32(value, Endianness.LittleEndian);
        }

        public static UInt64 littleEndian64(UInt64 value)
        {
            return byteOrder64(value, Endianness.LittleEndian);
        }

        public static UInt16 bigEndian16(UInt16 value)
        {
            return byteOrder16(value, Endianness.BigEndian);
        }
        public static UInt32 bigEndian32(UInt32 value)
        {
            return byteOrder32(value, Endianness.BigEndian);
        }
        public static UInt64 bigEndian64(UInt64 value)
        {
            return byteOrder64(value, Endianness.BigEndian);
        }

        private static UInt16 byteOrder16(UInt16 value, Endianness endian)
        {
            if ((endian == Endianness.BigEndian && BitConverter.IsLittleEndian)
                || (endian == Endianness.LittleEndian && !BitConverter.IsLittleEndian))
            {
                value = (UInt16)(
                    ((value << 8) & 0xff00)
                    | (value >> 8)
                );
            }
            return value;
        }

        private static UInt32 byteOrder32(UInt32 value, Endianness endian)
        {
            if ((endian == Endianness.BigEndian && BitConverter.IsLittleEndian)
                || (endian == Endianness.LittleEndian && !BitConverter.IsLittleEndian))
            {
                value = value << 24
                    | ((value << 8) & 0x00ff0000)
                    | ((value >> 8) & 0x0000ff00)
                    | (value >> 24);
            }

            return value;
        }

        private static UInt64 byteOrder64(UInt64 value, Endianness endian)
        {
            if ((endian == Endianness.BigEndian && BitConverter.IsLittleEndian)
                || (endian == Endianness.LittleEndian && !BitConverter.IsLittleEndian))
            {
                UInt32 high_part = byteOrder32((UInt32)(value >> 32), endian);
                UInt32 low_part = byteOrder32((UInt32)(value & 0xFFFFFFFF), endian);
                value = low_part;
                value <<= 32;
                value |= high_part;
            }
            return value;
        }

        public static bool isPrivate(this IPAddress address)
        {
            UInt32 addr, subNetPrivate, maskPrivate;
            byte[] addr6;

            switch (address.AddressFamily)
            { 
                case AddressFamily.InterNetwork:
                    addr = address.ToUInt32();

                    subNetPrivate = 0xC0A80000; // 192.168.0.0/16
                    maskPrivate = 0xFFFF0000;
                    if ((addr & maskPrivate) == subNetPrivate) return true;

                    subNetPrivate = 0xAC100000; // 172.16.0.0/12
                    maskPrivate = 0xFFF00000;
                    if ((addr & maskPrivate) == subNetPrivate) return true;

                    subNetPrivate = 0x0A000000; // 10.0.0.0/8
                    maskPrivate = 0xFF000000;
                    if ((addr & maskPrivate) == subNetPrivate) return true;

                    subNetPrivate = 0xA9FE0000; // 169.254.0.0/16
                    maskPrivate = 0xFFFF0000;
                    if ((addr & maskPrivate) == subNetPrivate) return true;
                    break;
                case AddressFamily.InterNetworkV6:
                    addr6 = address.GetAddressBytes();

                    // let's work only on first 32 bits as masks are very wide
                    if (addr6.Length != 16)
                        break;

                    addr = (UInt32)((addr6[0] << 24)
                         | (addr6[1] << 16)
                         | (addr6[2] << 8)
                         | (addr6[3]));

                    subNetPrivate = 0xFD000000; // fd00::/8
                    maskPrivate = 0xFF000000;
                    if ((addr & maskPrivate) == subNetPrivate) return true;

                    subNetPrivate = 0xFE800000;   // fe80::/10
                    maskPrivate = 0xFFC00000;
                    if ((addr & maskPrivate) == subNetPrivate) return true;
                    break;
            }
            return false;
        }

        // check if zeroconf (ipv4) or link-local (ipv6)
        public static bool isAutoConf(this IPAddress address)
        {
            UInt32 addr, subNetPrivate, maskPrivate;
            byte[] addr6;

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    addr = address.ToUInt32();

                    subNetPrivate = 0xA9FE0000; // 169.254.0.0/16
                    maskPrivate = 0xFFFF0000;
                    if ((addr & maskPrivate) == subNetPrivate) return true;
                    break;
                case AddressFamily.InterNetworkV6:
                    addr6 = address.GetAddressBytes();

                    // let's work only on first 32 bits as masks are very wide
                    if (addr6.Length != 16)
                        break;

                    addr = (UInt32)((addr6[0] << 24)
                         | (addr6[1] << 16)
                         | (addr6[2] << 8)
                         | (addr6[3]));

                    subNetPrivate = 0xFE800000;   // fe80::/10
                    maskPrivate = 0xFFC00000;
                    if ((addr & maskPrivate) == subNetPrivate) return true;
                    break;
            }
            return false;
        }

        public static UInt32 ToUInt32(this IPAddress ipv4)
        {
            byte[] IPBytes;

            IPBytes = ipv4.GetAddressBytes();

            // less efficient
            // return NetworkToHostOrder32(BitConverter.ToUInt32(address.GetAddressBytes(), 0));

            return (UInt32)((IPBytes[0] << 24)
                    | (IPBytes[1] << 16)
                    | (IPBytes[2] << 8)
                    | (IPBytes[3]));
        }
    }
}
