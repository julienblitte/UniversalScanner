using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace UniversalScanner
{
    public class UPnP : ScanEngine
    {
        protected new string multicastIP = "239.255.255.250";
        protected int port = 1900;

        public override int color
        {
            get
            {
                return Color.DarkGreen.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "UPnP";
            }
        }

        public UPnP()
        {
            listenMulticast(IPAddress.Parse(multicastIP), port);
            listenUdpInterfaces();
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
            return Encoding.UTF8.GetBytes(string.Format("M-SEARCH * HTTP/1.1\r\nHost: {0}:{1}\r\nST:upnp:rootdevice\r\nMan:\"ssdp:discover\"\r\nMX:2\r\n\r\n",
                    multicastIP, multicastPort));
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string deviceType, deviceID;
            string server;
            string[] serverDetails;
            string body;

            body = Encoding.UTF8.GetString(data);

            server = extractHttpVar(body, "SERVER");
            serverDetails = splitServerDetails(server);
            
            if (serverDetails.Length > 0)
            {
                deviceType = serverDetails[serverDetails.Length - 1];
            }
            else
            {
                deviceType = "anonymous";
            }

            deviceID = extractHttpVar(body, "USN");

            if (viewer != null && deviceID != "" )
            {
                viewer.deviceFound(name, 0, from.Address, deviceType, extractUUID(deviceID));
            }
        }

        private string[] splitServerDetails(string device)
        {
            Regex reg;
            string[] result;

            // values can be separated by a comma or a space
            // values are generally this format: name/version
            // "/version" can be ommited when comma are used as separator
            reg = new Regex("[^,/]+(/[^ ,]+)?");
            var foundComp = reg.Matches(device);

            result = new string[foundComp.Count];
            for(int i = 0; i< foundComp.Count; i++)
            {
                result[i] = foundComp[i].Value.Trim();
            }

            return result;
        }

        private string extractUUID(string USN)
        {
            int s = USN.IndexOf("::");
            if (s >= 0)
            {
                USN = USN.Substring(0, s);
            }
            if (USN.StartsWith("uuid:"))
            {
                USN = USN.Substring(5);
            }

            return USN;
        }

        private string extractHttpVar(string data, string variable)
        {
            string[] lines = data.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            if (lines.Length < 2)
                return "";

            for(int i=1; i < lines.Length; i++)
            {
                int s = lines[i].IndexOf(":");
                if (s >= 0)
                {
                    string a = lines[i].Substring(0, s);
                    string b = lines[i].Substring(s + 1);

                    if (a.Trim().ToUpper() == variable.ToUpper())
                    {
                        return b.Trim();
                    }
                }
            }

            return "";
        }

    }
}