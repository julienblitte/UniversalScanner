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
        // NetworkToHostOrder and HostToNetworkOrder are unsafe due type overload
        // UInt64 ntohll(UInt64) and UInt64 htonll(UInt64) defined bellow
        [DllImport("wsock32.dll")]
        public static extern UInt32 ntohl(UInt32 value);
        [DllImport("wsock32.dll")]
        public static extern UInt32 htonl(UInt32 value);
        [DllImport("wsock32.dll")]
        public static extern UInt16 ntohs(UInt16 value);
        [DllImport("wsock32.dll")]
        public static extern UInt16 htons(UInt16 value);

        public static bool isPrivateIPv4Network(IPAddress address)
        {
            UInt32 addr, subNetPrivate, maskPrivate;

            addr = ntohl(BitConverter.ToUInt32(address.GetAddressBytes(), 0));

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

            return false;
        }

        public static UInt64 htonll(UInt64 value)
        {
            if (htonl(1) != 1)
            {
                UInt32 high_part = htonl((UInt32)(value >> 32));
                UInt32 low_part = htonl((UInt32)(value & 0xFFFFFFFF));
                value = low_part;
                value <<= 32;
                value |= high_part;
            }
            return value;
        }
        public static UInt64 ntohll(UInt64 value)
        {
            if (ntohl(1) != 1)
            {
                UInt32 high_part = ntohl((UInt32)(value >> 32));
                UInt32 low_part = ntohl((UInt32)(value & 0xFFFFFFFF));
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
                    addr = ntohl(BitConverter.ToUInt32(address.GetAddressBytes(), 0));

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
    }
}
