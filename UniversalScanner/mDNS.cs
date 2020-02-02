using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class mDNS : ScanEngine
    {
        protected new string multicastIP = "224.0.0.251";
        protected int port = 5353;

        public delegate void mDNSAnswerTypeA_Action(string domainFilter, IPAddress address);
        protected Dictionary<string, mDNSAnswerTypeA_Action> resolutionTable;

        private UInt16 mDNSQuestionClass = 0x0001;

        public enum mDNSType : UInt16
        {
            TYPE_A = 0x0001,     // ipv4
            TYPE_PTR = 0x000C,   // domain
            TYPE_TXT = 0x0010,   // string
            TYPE_AAAA = 0x001C,  // ipv6
            TYPE_SRV = 0x0021,   // server service
            TYPE_ANY = 0x00ff    // any
        };


        [StructLayout(LayoutKind.Explicit, Size = 12, CharSet = CharSet.Ansi)]
        public struct mDNSHeader
        {
            [FieldOffset(0)] public UInt16 transactionID;
            [FieldOffset(2)] public UInt16 flags;
            [FieldOffset(4)] public UInt16 questions;
            [FieldOffset(6)] public UInt16 answerRRs;
            [FieldOffset(8)] public UInt16 authorityRRs;
            [FieldOffset(10)] public UInt16 additionalRRs;
        }

        public mDNS()
        {
            listenMulticast(IPAddress.Parse(multicastIP), port);
            listenUdpGlobal(port, true);

            resolutionTable = new Dictionary<string, mDNSAnswerTypeA_Action>();
        }

        public void registerDomain(string domainFilter, mDNSAnswerTypeA_Action onResolve)
        {
            resolutionTable.Add(domainFilter, onResolve);
        }

        private byte[] buildQuery(string queryString, mDNSType queryType)
        {
            byte[] result;
            string[] subDomains;
            int querySize, i;

            IdnMapping idn = new IdnMapping();

            subDomains = idn.GetAscii(queryString).Split('.');

            // compute size of byte needed
            querySize = 0;
            foreach (var d in subDomains)
            {
                querySize += 1 + Encoding.ASCII.GetBytes(d).Length;
            }
            querySize++; // NULL string termination; 
            querySize += 4; // type + questionClass; 
            result = new byte[querySize];

            // generate query
            i = 0;
            foreach (var d in subDomains)
            {
                byte[] currentSubDomain;
                result[i] = (byte)d.Length;
                i++;

                currentSubDomain = Encoding.ASCII.GetBytes(d);
                currentSubDomain.CopyTo(result, i);
                i += currentSubDomain.Length;
            }
            result[i++] = 0x00; // NULL string termination; 

            result[i] = (byte)((((UInt16)queryType) << 8) & 0xff);
            result[i + 1] = (byte)(((UInt16)queryType) & 0xff);
            i += 2;
            result[i++] = (byte)((mDNSQuestionClass << 8) & 0xff); // mDNSQuestionClass
            result[i++] = (byte)((mDNSQuestionClass) & 0xff);

            return result;
        }

        public void scan(string queryString, mDNSType queryType)
        {
            byte[] data;
            byte[] query;
            mDNSHeader header;
            int headerSize;
            IPEndPoint endpoint;

            header = new mDNSHeader() { transactionID = 0, flags = 0, questions = ntohs(1), answerRRs = 0, authorityRRs = 0, additionalRRs = 0 };
            query = buildQuery(queryString, queryType);

            headerSize = Marshal.SizeOf(header);
            data = new byte[headerSize + query.Length];
            IntPtr ptr = Marshal.AllocHGlobal(headerSize);
            try
            {
                Marshal.StructureToPtr<mDNSHeader>(header, ptr, false);
                Marshal.Copy(ptr, data, 0, headerSize);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
            query.CopyTo(data, headerSize);

            endpoint = new IPEndPoint(IPAddress.Parse(multicastIP), port);
            if (globalListener.inUse)
            {
                try
                {
                    globalListener.udp.Send(data, data.Length, endpoint);
                }
                catch
                {
                    Trace.WriteLine("Error: mDNS.scan(): Unable to send data to {0}!", endpoint.ToString());
                }
            }
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            mDNSHeader header;
            int headerSize;
            int expectedQueries, expectedResponses;
            int position;

            headerSize = Marshal.SizeOf(typeof(mDNSHeader));

            if (data.Length <= headerSize)
            {
                Trace.WriteLine("mDNS.reciever(): Warning: invlaid packet size.");
                return;
            }

            IntPtr ptr = Marshal.AllocHGlobal(headerSize);
            try
            {
                Marshal.Copy(data, 0, ptr, headerSize);
                header = Marshal.PtrToStructure<mDNSHeader>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            expectedQueries = ntohs(header.questions);
            expectedResponses = ntohs(header.authorityRRs) + ntohs(header.answerRRs) + ntohs(header.additionalRRs);
            if (expectedResponses > 0)
            {
                position = headerSize;
                readQueries(data, ref position, expectedQueries);
                readResponses(data, ref position, expectedResponses);
            }
        }

        private void readQueries(byte[] data, ref int position, int expectedQueries)
        {
            UInt16 queryType, questionClass;
            string name;

            while (position < data.Length && expectedQueries > 0)
            {
                name = readString(data, ref position);
                queryType = readUInt16(data, ref position);
                questionClass = readUInt16(data, ref position);
                Trace.WriteLine(String.Format("mDNS Query '{0}', type = {1}", name, queryType));

                expectedQueries--;
            }
        }

        private void readResponses(byte[] data, ref int position, int expectedAnswers)
        {
            UInt16 answerType, flushClass, dataLen;
            UInt32 ttl;
            string name;

            while (position < data.Length && expectedAnswers > 0)
            {
                name = readString(data, ref position);
                answerType = readUInt16(data, ref position);
                Trace.WriteLine(String.Format("mDNS Response '{0}', type = {1}:", name, answerType));

                flushClass = readUInt16(data, ref position);
                ttl = readUInt32(data, ref position);
                dataLen = readUInt16(data, ref position);

                if (position + dataLen > data.Length)
                {
                    Trace.WriteLine("Error: readResponses(): packet parsing overflow!");
                    return;
                }

                switch (answerType)
                {
                    case (UInt16)mDNSType.TYPE_A:
                        IPAddress ip;
                        ip = readAnswer_A(data, ref position, dataLen);
                        Trace.WriteLine("mDNS IPv4(A): " + ip.ToString());
                        break;
                    case (UInt16)mDNSType.TYPE_PTR:
                        string domain;
                        domain = readAnswer_PTR(data, ref position, dataLen);
                        Trace.WriteLine(String.Format("mDNS domain(PTR): '{0}'", domain));
                        return;
                    case (UInt16)mDNSType.TYPE_TXT:
                        string[] str;
                        str = readAnswer_TXT(data, ref position, dataLen);
                        foreach(string t in str)
                        {
                            Trace.WriteLine(String.Format("mDNS IPv6(TXT): '{0}'", t));
                        }
                        return;
                    case (UInt16)mDNSType.TYPE_AAAA:
                        IPAddress ipv6;
                        ipv6 = readAnswer_AAAA(data, ref position, dataLen);
                        Trace.WriteLine(String.Format("mDNS IPv6(AAAA): '{0}'", ipv6.ToString()));
                        return;
                    case (UInt16)mDNSType.TYPE_SRV:
                        string srv;
                        srv = readAnswer_SRV(data, ref position, dataLen);
                        Trace.WriteLine(String.Format("mDNS server(SRV): '{0}'", srv));
                        return;
                    default:
                        Trace.WriteLine(String.Format("mDNS packet type {0} not implemented, parsing of this packet aborted!", answerType));
                        return;
                }
                expectedAnswers--;
            }
        }

        private IPAddress readAnswer_A(byte[] data, ref int position, int dataLen)
        {
            UInt32 ipVal;

            if (dataLen != 4)
            {
                Trace.WriteLine("Error: readAnswer_A(): Invalid address size!");
                return IPAddress.Any;
            }

            ipVal = readUInt32(data, ref position);
            return (new IPAddress(ipVal));
        }

        private IPAddress readAnswer_AAAA(byte[] data, ref int position, int dataLen)
        {
            byte[] ipAddressBytes;

            if (dataLen != 16)
            {
                Trace.WriteLine("Error: readAnswer_AAAA(): Invalid address size!");
                return IPAddress.Any;
            }

            ipAddressBytes = new byte[16];
            Array.Copy(data, position, ipAddressBytes, 0, 16);
            return (new IPAddress(ipAddressBytes));
        }

        private string readAnswer_PTR(byte[] data, ref int position, int dataLen)
        {
            return readString(data, ref position);
        }

        private string[] readAnswer_TXT(byte[] data, ref int position, int dataLen)
        {
            byte len;
            StringBuilder sb;
            List<string> result;

            result = new List<string>();

            while (dataLen > 1 && position+1 < data.Length)
            {
                len = data[position];
                position++;
                dataLen--;

                sb = new StringBuilder();
                while (len > 0 && dataLen > 0 && position < data.Length)
                {
                    sb.Append(Convert.ToChar(data[position]));
                    position++;
                    dataLen--;
                    len--;
                }
                result.Add(sb.ToString());
            }

            return result.ToArray();
        }

        private string readAnswer_SRV(byte[] data, ref int position, int dataLen)
        {
            UInt16 priority, weight, port;

            if (dataLen < 6)
            {
                Trace.WriteLine("Error: readAnswer_SRV(): packet data size error!");
                return "";
            }

            priority = readUInt16(data, ref position);
            weight = readUInt16(data, ref position);
            port = readUInt16(data, ref position);

            return String.Format("{0}:{1}", readString(data, ref position), port);
        }

        private UInt16 readUInt16(byte[] data, ref int position)
        {
            UInt16 result;

            result = 0;
            if (position + 2 > data.Length)
            {
                Trace.WriteLine("Error: readUInt16(): packet parsing overflow!");
                return 0;
            }

            result |= data[position];
            position++;
            result <<= 8;
            result |= data[position];
            position++;

            return result;
        }

        private UInt32 readUInt32(byte[] data, ref int position)
        {
            UInt32 result;

            result = 0;
            if (position + 4 > data.Length)
            {
                Trace.WriteLine("Error: readUInt32(): packet parsing overflow!");
                return 0;
            }

            result |= data[position];
            position++;
            result <<= 8;
            result |= data[position];
            position++;
            result <<= 8;
            result |= data[position];
            position++;
            result <<= 8;
            result |= data[position];
            position++;

            return result;
        }

        private string readString(byte[] data, ref int position)
        {
            byte len;
            StringBuilder sb;

            sb = null;
            while (position < data.Length)
            {
                len = data[position];
                position++;

                if (len == 0)
                {
                    return (sb != null ? sb.ToString() : "");
                }

                if (sb == null)
                {
                    sb = new StringBuilder();
                }
                else
                {
                    sb.Append('.');
                }

                if ((len & 0xC0) == 0xC0)
                {
                    int position_temp;
                    byte len_temp;

                    position_temp = ((len << 8) | (data[position])) & 0x03FF;
                    position++;

                    if (position_temp > data.Length)
                    {
                        break;
                    }

                    len_temp = data[position_temp];
                    position_temp++;

                    while (len_temp > 0 && data[position_temp] != 0 && position_temp < data.Length)
                    {
                        sb.Append(Convert.ToChar(data[position_temp]));

                        len_temp--;
                        position_temp++;
                    }

                    return sb.ToString();
                }
                else
                {
                    while (len > 0 && position < data.Length)
                    {
                        sb.Append(Convert.ToChar(data[position]));
                        position++;
                        len--;
                    }
                }
            }
            Trace.WriteLine("Error: readString(): packet parsing overflow!");
            return (sb != null ? sb.ToString() : "");
        }

        public override void scan()
        {
            // do nothing, different packet should be sent by each plugin
            return;
        }

        public override byte[] sender(IPEndPoint dest)
        {
            throw new NotImplementedException();
        } 
    }
}
