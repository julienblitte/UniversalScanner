using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class Wsdiscovery : ScanEngine
    {
        private const int port = 3702;
        private new readonly string multicastIP = "239.255.255.250";

        private Guid message_uuidg;
        private string announce = "<s:Envelope"
            + " xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
            + " xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
            + " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
            + " xmlns:w=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\""
            + " xmlns:o=\"http://www.onvif.org/ver10/device/wsdl\""
            + ">"
            + "<s:Header>"
            + "<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>"
            + "<a:MessageID>urn:uuid:{0}</a:MessageID>"
            + "<a:To s:mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
            + "<a:ReplyTo>"
            + "<a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>"
            + "</a:ReplyTo>"
            + "</s:Header>"
            + "<s:Body>"
            + "<d:Probe>"
            + "<d:Types>w:Device o:Device</d:Types>"
            + "</d:Probe>"
            + "</s:Body>"
            + "</s:Envelope>";

        public override int color
        {
            get
            {
                return 0x404040;
            }
        }
        public override string name
        {
            get
            {
                return "WSDiscovery";
            }
        }

        public Wsdiscovery()
        {
            listenMulticast(IPAddress.Parse(multicastIP), port);
            listenUdpInterfaces();
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string xml;
            Regex urn = new Regex("[<:]Address>([^<>]+)</");
            Regex model = new Regex("[<:]Types>([^<>]+)</");
            Regex url = new Regex("[<:]XAddrs>([^<>]+)</");
            Match m;

            string deviceModel, deviceSerial;

            deviceModel = "";
            deviceSerial = "";
            try
            {
                xml = Encoding.UTF8.GetString(data);

                m = urn.Match(xml);
                if (m.Success)
                {
                    deviceSerial = extractUUID(m.Groups[1].Value);
                }

                m = model.Match(xml);
                if (m.Success)
                {
                    deviceModel = removeNameSpace(m.Groups[1].Value);
                }

                m = url.Match(xml);
                if (m.Success)
                {
                    // find all url
                }

            }
            catch (Exception)
            {
                Logger.WriteLine(Logger.DebugLevel.Warn, "Wsdiscovery.reciever(): Error: Unable to read text");
            }

            if (viewer != null && deviceModel != "" && deviceSerial != "")
            {
                viewer.deviceFound(name, 0, from.Address, deviceModel, deviceSerial);
            }
        }

        public override void scan()
        {
#if DEBUG
            selfTest();
#endif
            sendMulticast(IPAddress.Parse(multicastIP), port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            string announce_instance;
            message_uuidg = Guid.NewGuid();

            announce_instance = String.Format(announce, message_uuidg);
            return Encoding.ASCII.GetBytes(announce_instance);
        }

        private string extractUUID(string USN)
        {
            if (USN.StartsWith("urn:"))
            {
                USN = USN.Substring(4);
            }
            
            if (USN.StartsWith("uuid:"))
            {
                USN = USN.Substring(5);
            }

            return USN;
        }

        private string removeNameSpace(string value)
        {
            Regex xmlns;

            xmlns = new Regex("[a-zA-Z_][a-zA-Z_0-9-]*:");

            return xmlns.Replace(value, "");
        }
    }
}
