using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    class PortProvider
    {
        private static List<ushort> reserved;
        private static List<int> usedPorts;
        private static PortProvider instance=null;
        private static Random rand; 

        public static PortProvider getInstance()
        {
            if (instance == null)
            {
                instance = new PortProvider();
            }

            return instance;
        }

        private PortProvider()
        {
            reserved = new List<ushort>();
            usedPorts = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Select(l => l.Port).ToList();
            rand = new Random();
        }

        public void reserveUDP(UInt16[] port)
        {
            // add lock for multithread ?
            foreach(var p in port)
            {
                reserved.Add(p);
            }
        }

        public int getFreeUdpPort()
        {
            int[] portRange = { 1024, 65534 };
            IEnumerable<int> portsUseable, portsFree;
            int countFree;

            portsUseable = Enumerable.Range(portRange[0], portRange[1] - portRange[0]);

            portsFree = portsUseable.Except(usedPorts).Except(reserved.Select(p => (int)p));

            countFree = portsFree.Count();
            if (countFree == 0)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Fatal, "Error: UdpFreePortProvider(): No free UDP port!");
                return -1;
            }

            int index = rand.Next(0, countFree);

            return portsFree.ElementAt(index);
        }
    }
}
