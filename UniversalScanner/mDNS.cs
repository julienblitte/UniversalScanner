using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class mDNS : ScanEngine
    {
        protected new string multicastIP = "224.0.0.251";
        protected int port = 5353;

        public delegate void mDNSAnswerTypeA(string domain, IPAddress address);
        protected Dictionary<string, mDNSAnswerTypeA> resolutionTable;

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
            listenUdpInterfaces();

            resolutionTable = new Dictionary<string, mDNSAnswerTypeA>();
        }

        public void registerDomain(string domain, mDNSAnswerTypeA onResolve)
        {
            resolutionTable.Add(domain, onResolve);
        }

        public void scan(string domain)
        {
            byte[] data;
            mDNSHeader header;
            IPEndPoint endpoint;

            header = new mDNSHeader() { transactionID=0, flags=0, questions=1, answerRRs=0, authorityRRs=0, additionalRRs=0 };
            // TODO: build a customized mDNS packet query
            // TODO: build a customized mDNS packet with header and query
            data = new byte[0];

            endpoint = new IPEndPoint(IPAddress.Parse(multicastIP), port);

            foreach (networkBundle net in interfacesListerner)
            {
                if (net.inUse)
                {
                    try
                    {
                        net.udp.Send(data, data.Length, endpoint);
                    }
                    catch (Exception) { }
                }
            }
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            // TODO: analyze recieved packet and look into resolutionTable for a valid entry, if found call onResolve
        }

        public override void scan()
        {
            // do nothing, packet should be sent by each plugin
            return;
        }

        public override byte[] sender(IPEndPoint dest)
        {
            throw new NotImplementedException();
        } 
    }
}
