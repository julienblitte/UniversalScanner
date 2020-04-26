using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace UniversalScanner
{
    public enum mDNSType : UInt16
    {
        TYPE_A = 0x0001,     // ipv4
        TYPE_PTR = 0x000C,   // domain
        TYPE_TXT = 0x0010,   // string
        TYPE_AAAA = 0x001C,  // ipv6
        TYPE_SRV = 0x0021,   // server service
        TYPE_ANY = 0x00ff    // any
    };

    public struct mDNSAnswer
    {
        public mDNSType Type;
        public mDNSAnswerData data;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct mDNSAnswerData  /* union struct */
    {
        [FieldOffset(0)] public IPAddress typeA;
        [FieldOffset(0)] public string typePTR;
        [FieldOffset(0)] public string[] typeTXT;
        [FieldOffset(0)] public IPAddress typeAAAA;
        [FieldOffset(0)] public mDNSAnswerDataSRV typeSRV;
    }

    public struct mDNSAnswerDataSRV
    {
        public UInt16 priority;
        public UInt16 weight;
        public UInt16 port;
        public string domain;
    }

    class mDNS : ScanEngine
    {
        protected new string multicastIP = "224.0.0.251";
        protected int port = 5353;

        protected static mDNS globalInstance = null;
        protected static object locker = new Object();

        public override int color
        {
            get
            {
                return Color.Black.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "mDNS";
            }
        }

        public delegate void mDNSResponse_Action(string domainFilter, mDNSAnswer[] answers);

        protected Dictionary<string, mDNSResponse_Action> resolutionTable;

        private UInt16 mDNSQuestionClass = 0x0001;

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

        private mDNS()
        {
            listenMulticast(IPAddress.Parse(multicastIP), port);
            listenUdpInterfaces();

            resolutionTable = new Dictionary<string, mDNSResponse_Action>();
        }

        public static mDNS getInstance()
        {
            lock(locker) // avoid class instance to run in two threads same time
            {
                if (globalInstance == null)
                {
                    globalInstance = new mDNS();
                }
            }

            return globalInstance;
        }

        public void registerDomain(string domainFilter, mDNSResponse_Action onResponse)
        {
            resolutionTable.Add(domainFilter, onResponse);
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
            byte[] headerBytes;
            IPEndPoint endpoint;

            header = new mDNSHeader() { transactionID = 0, flags = 0, questions = NetworkUtils.ntohs(1), answerRRs = 0, authorityRRs = 0, additionalRRs = 0 };
            query = buildQuery(queryString, queryType);

            headerBytes = header.GetBytes();

            data = new byte[headerBytes.Length + query.Length];
            headerBytes.CopyTo(data, 0);
            query.CopyTo(data, headerBytes.Length);

            endpoint = new IPEndPoint(IPAddress.Parse(multicastIP), port);

            if (globalListener.inUse)
            {
                try
                {
                   Logger.WriteLine(Logger.DebugLevel.Info, String.Format("{0} -> {1}", globalListener.endPoint.ToString(), endpoint.ToString()));
                    globalListener.udp.Send(data, data.Length, endpoint);
                }
                catch
                {
                   Logger.WriteLine(Logger.DebugLevel.Error, String.Format("Error: mDNS.scan(): Unable to send data to {0}!", endpoint.ToString()));
                }
            }

            if (interfacesListerner != null)
            {
                foreach (networkBundle net in interfacesListerner)
                {
                    if (net.inUse)
                    {
                       Logger.WriteLine(Logger.DebugLevel.Info, String.Format("{0} -> {1}", net.endPoint.ToString(), endpoint.ToString()));
                        try
                        {
                            net.udp.Send(data, data.Length, endpoint);
                        }
                        catch
                        {
                           Logger.WriteLine(Logger.DebugLevel.Error, String.Format("Error: mDNS.scan(): Unable to send data to {0}!", endpoint.ToString()));
                        }
                    }
                }
            }
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            mDNSHeader header;
            int headerSize;
            int expectedQueries, expectedAnwers;
            int position;

            headerSize = typeof(mDNSHeader).StructLayoutAttribute.Size;

            if (data.Length <= headerSize)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: mDNS.reciever(): invalid packet size.");
                Logger.WriteData(Logger.DebugLevel.Warn, data);
                return;
            }

            header = data.GetStruct<mDNSHeader>();

            expectedQueries = NetworkUtils.ntohs(header.questions);
            expectedAnwers = NetworkUtils.ntohs(header.authorityRRs) + NetworkUtils.ntohs(header.answerRRs) + NetworkUtils.ntohs(header.additionalRRs);
            if (expectedAnwers > 0)
            {
                position = headerSize;
                try
                {
                    readQueries(data, ref position, expectedQueries);
                    readAnswers(data, ref position, expectedAnwers);
                }
                catch (OverflowException ex)
                {
                   Logger.WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: mDNS.reciever(): packet parsing overflow at position 0x{0:X}!", position));
                   Logger.WriteLine(Logger.DebugLevel.Warn, ex.ToString());
                    Logger.WriteData(Logger.DebugLevel.Warn, data);
                }
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
               Logger.WriteLine(Logger.DebugLevel.Debug, String.Format("mDNS Query '{0}', type = {1}", name, queryType));

                expectedQueries--;
            }
        }

        private void readAnswers(byte[] data, ref int position, int expectedAnswers)
        {
            UInt16 answerType, flushClass, dataLen;
            UInt32 ttl;
            string name;
            mDNSAnswer[] answers;
            int answerIndex;
            string triggerName;

            answers = new mDNSAnswer[expectedAnswers];
            answerIndex = 0;
            triggerName = null;
            while (position < data.Length && answerIndex < expectedAnswers)
            {
                name = readString(data, ref position);
                answerType = readUInt16(data, ref position);
                flushClass = readUInt16(data, ref position);
                ttl = readUInt32(data, ref position);
                dataLen = readUInt16(data, ref position);

                if (position + dataLen > data.Length)
                {
                    throw new OverflowException(String.Format("mDNS answer parsing overflow"));
                }

                answers[answerIndex].Type = (mDNSType)answerType;
                switch (answerType)
                {
                    case (UInt16)mDNSType.TYPE_A:
                        IPAddress ip;
                        ip = readAnswer_A(data, ref position, dataLen);
                        answers[answerIndex].data.typeA = ip;
                       Logger.WriteLine(Logger.DebugLevel.Debug, String.Format("* mDNS answer for '{0}': IPv4 (A) = {1}", name, ip.ToString()));
                        break;
                    case (UInt16)mDNSType.TYPE_PTR:
                        string domain;
                        domain = readAnswer_PTR(data, ref position, dataLen);
                        answers[answerIndex].data.typePTR = domain;
                       Logger.WriteLine(Logger.DebugLevel.Debug, String.Format("* mDNS answer for '{0}': Domain (PTR) = '{1}'", name, domain));
                        break;
                    case (UInt16)mDNSType.TYPE_TXT:
                        string[] str;
                        str = readAnswer_TXT(data, ref position, dataLen);
                        answers[answerIndex].data.typeTXT = str;
                        foreach (string t in str)
                        {
                           Logger.WriteLine(Logger.DebugLevel.Debug, String.Format("* mDNS answer for '{0}': Text (TXT) = '{1}'", name, t));
                        }
                        break;
                    case (UInt16)mDNSType.TYPE_AAAA:
                        IPAddress ipv6;
                        ipv6 = readAnswer_AAAA(data, ref position, dataLen);
                        answers[answerIndex].data.typeAAAA = ipv6;
                       Logger.WriteLine(Logger.DebugLevel.Debug, String.Format("* mDNS answer for {0}: IPv6 (AAAA) = {1}", name, ipv6.ToString()));
                        break;
                    case (UInt16)mDNSType.TYPE_SRV:
                        mDNSAnswerDataSRV srv;
                        srv = readAnswer_SRV(data, ref position, dataLen);
                        answers[answerIndex].data.typeSRV = srv;
                       Logger.WriteLine(Logger.DebugLevel.Debug, String.Format("* mDNS answer for '{0}': Server (SRV) = '{1}:{2}'", name, srv.domain, srv.port));
                        break;
                    default:
                       Logger.WriteLine(Logger.DebugLevel.Debug, String.Format("* mDNS answer packet type {0} not implemented, parsing of this packet aborted!", answerType));
                        Array.Resize<mDNSAnswer>(ref answers, answerIndex);
                        goto readAnswers_abort;
                }
                if (resolutionTable.ContainsKey(name) && triggerName == null)
                {
                    triggerName = name;
                }
                answerIndex++;
            }
        readAnswers_abort:
            if (triggerName != null)
            {
                resolutionTable[triggerName].Invoke(triggerName, answers);
            }
        }

        private IPAddress readAnswer_A(byte[] data, ref int position, int dataLen)
        {
            UInt32 ipVal;

            if (dataLen != 4)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: readAnswer_A(): Invalid address size!");
                return IPAddress.Any;
            }

            ipVal = NetworkUtils.ntohl(readUInt32(data, ref position));
            return (new IPAddress(ipVal));
        }

        private IPAddress readAnswer_AAAA(byte[] data, ref int position, int dataLen)
        {
            byte[] ipAddressBytes;

            if (dataLen != 16)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: readAnswer_AAAA(): Invalid address size!");
                return IPAddress.Any;
            }

            ipAddressBytes = new byte[16];
            Array.Copy(data, position, ipAddressBytes, 0, 16);
            position += 16;
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

        private mDNSAnswerDataSRV readAnswer_SRV(byte[] data, ref int position, int dataLen)
        {
            mDNSAnswerDataSRV result;
            if (dataLen < 6)
            {
               Logger.WriteLine(Logger.DebugLevel.Warn, "Warning: readAnswer_SRV(): packet data size error!");
                result = new mDNSAnswerDataSRV { priority = 0, weight = 0, port = 0, domain=null };
                return result;
            }

            result = new mDNSAnswerDataSRV();
            result.priority = readUInt16(data, ref position);
            result.weight = readUInt16(data, ref position);
            result.port = readUInt16(data, ref position);
            result.domain = readString(data, ref position);

            return result;
        }

        private UInt16 readUInt16(byte[] data, ref int position)
        {
            UInt16 result;

            result = 0;
            if (position + 2 > data.Length)
            {
                throw new OverflowException(String.Format("mDNS UInt16 parsing overflow"));
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
                throw new OverflowException(String.Format("mDNS UInt32 parsing overflow"));
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
                    int positionPtr;

                    positionPtr = ((len << 8) | (data[position])) & 0x03FF;
                    position++;

                    if (positionPtr > data.Length)
                    {
                        break;
                    }

                    sb.Append(readString(data, ref positionPtr));
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
            throw new OverflowException(String.Format("mDNS string parsing overflow"));
        }

        public override void scan()
        {
            throw new NotImplementedException();
        }

        public override byte[] sender(IPEndPoint dest)
        {
            throw new NotImplementedException();
        }
    }
}
