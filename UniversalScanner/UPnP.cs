using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace UniversalScanner
{
    public class UPnP : ScanEngine
    {
        protected new string multicastIP = "239.255.255.250";
        protected int port = 1900;

        public UPnP()
        {
            listenMulticast(IPAddress.Parse(multicastIP), port);
            listenUdpInterfaces();
        }

        public override void scan()
        {
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
            string NT;
            bool announcement;
            string deviceIP, deviceType, deviceID;
            string body;

            body = Encoding.UTF8.GetString(data);

            // multicast
            NT = extractHttpVar(body, "NT");
            announcement = (NT == "upnp:rootdevice");

            deviceIP = from.Address.ToString();
            deviceType = extractHttpVar(body, "SERVER");
            deviceID = extractHttpVar(body, "USN");

            if (viewer != null && deviceIP != "" && deviceType != "" && deviceID != "")
                viewer.deviceFound("SSDP", deviceIP, extractDeviceDetail(deviceType, deviceDetailSection.DeviceType), extractUUID(deviceID), Color.DarkGreen.ToArgb());
        }

        private enum deviceDetailSection {OS=0, UPnPVersion=1, DeviceType=2};
        private string extractDeviceDetail(string device, deviceDetailSection section)
        {
            var deviceTable = device.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);

            
            if (deviceTable.Length >= Enum.GetNames(typeof(deviceDetailSection)).Length -1)
            {
                return deviceTable[(int)section].Trim();
            }
            return device;
        }

        private string extractUUID(string USN)
        {
            int s = USN.IndexOf("::");
            if (s >= 0)
            {
                string a = USN.Substring(0, s);
                if (a.StartsWith("uuid:"))
                {
                    return a.Substring(5);
                }
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