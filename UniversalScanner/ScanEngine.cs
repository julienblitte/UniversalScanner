using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UniversalScanner
{
    public delegate void scan();
    public interface ScannerViewer
    {
        void deviceFound(string protocol, int version, string deviceIP, string deviceType, string serial);
        event scan scanEvent;
        void formatProtocol(string protocol, int color);
    }

    public abstract class ScanEngine : IDisposable
    {
        protected IPAddress multicastIP;
        protected int multicastPort = 0;

        protected Thread scannerThread = null;
        protected int scannerPort = 0;

        protected ScannerViewer viewer = null;

        protected bool closing = false;
        public bool isDisposed = false;

        protected enum debugLevel { Fatal = 0, Error = 1, Warn = 2, Info = 3, Debug = 4 };
#if DEBUG
        protected readonly debugLevel currentDebugLevel = debugLevel.Debug;
#else
        protected readonly debugLevel currentDebugLevel = debugLevel.Info;
#endif

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

        protected struct networkBundle
        {
            public bool inUse;
            public Thread thread;
            public UdpClient udp;
            public IPEndPoint endPoint;
        };

        protected networkBundle globalListener;
        protected networkBundle multicastListener;
        protected networkBundle[] interfacesListerner;

        public abstract int color { get; }
        public abstract string name { get; }

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

        public ScanEngine()
        {
            globalListener.inUse = false;
            multicastListener.inUse = false;
        }

        public abstract void scan();

        protected void traceWriteData(debugLevel level, byte[] data, int threadId = 0)
        {
            string textFromData;
            bool isBinary;
            string[] lines;
            StringBuilder result;
            Regex binaryCharacters;

            if (level > currentDebugLevel)
            {
                return;
            }

            if (threadId == 0)
            {
                threadId = Thread.CurrentThread.ManagedThreadId;
            }

            textFromData = "";
            try
            {
                textFromData = Encoding.UTF8.GetString(data);
                binaryCharacters = new Regex("[^\x20-\x7E\t\r\n]");
                isBinary = binaryCharacters.IsMatch(textFromData);
            }
            catch
            {
                isBinary = true;
            }

            result = new StringBuilder();
            if (isBinary)
            {

                for (int i = 0; i < data.Length; i++)
                {
                    if (i % 16 == 0 && i > 0)
                    {
                        result.AppendFormat("\n[{0,4}] ", threadId);
                    }
                    result.AppendFormat(" {0:X02}", (byte)data[i]);
                }
            }
            else
            {
                lines = Regex.Split(textFromData, "\r\n|\r|\n");

                foreach (string line in lines)
                {
                    result.AppendFormat("\n[{0,4}] {1}", threadId, line);
                }

            }

            Trace.WriteLineIf(level <= currentDebugLevel, String.Format("[{0,4}] {1}", threadId, result.ToString()));
        }

        protected void traceWriteLine(debugLevel level, string line, int threadId = 0)
        {
            if (threadId == 0)
            {
                threadId = Thread.CurrentThread.ManagedThreadId;
            }

            Trace.WriteLineIf(level <= currentDebugLevel, String.Format("[{0,4}] {1}", threadId, line));
        }

        public int listenUdpGlobal(int localPort = 0)
        {
            if (localPort != 0)
            {
                if (!isFreeUdpPort(localPort))
                {
                    traceWriteLine(debugLevel.Info, String.Format("Error: ScanEngine.listenUdpGlobal(): Local UDP port {0} is already in use...", localPort));
                    return -1;
                }
            }
            else
            {
                localPort = getFreeUdpPort();
            }

            try
            {
                /* configure UdpClient and EndPoint */
                globalListener.udp = new UdpClient();
                globalListener.udp.EnableBroadcast = true;
                globalListener.endPoint = new IPEndPoint(IPAddress.Any, localPort);

                // start unicast reciever on main interface
                globalListener.thread = new Thread(unicastReciever);
                globalListener.thread.IsBackground = true;

                globalListener.inUse = true;

                traceWriteLine(debugLevel.Info, String.Format("Listening on {0}...", globalListener.endPoint.ToString()), globalListener.thread.ManagedThreadId);
            }
            catch
            {
                globalListener.inUse = false;
                return -1;
            }
            globalListener.thread.Start();

            return localPort;
        }

        public void listenUdpInterfaces()
        {
            int len;
            List<IPAddress> addresses;

            addresses = new List<IPAddress>();
            foreach (var iface in listActiveInterface())
            {
                addresses.AddRange(listInterfaceAddresses(iface, AddressFamily.InterNetwork));
            }

            len = addresses.Count();
            interfacesListerner = new networkBundle[len];

            for (int i = 0; i < len; i++)
            {
                int localPort = getFreeUdpPort();
                IPAddress address = addresses[i];
                try
                {
                    // configure UdpClient and EndPoint
                    interfacesListerner[i].udp = new UdpClient();
                    interfacesListerner[i].udp.EnableBroadcast = true;
                    interfacesListerner[i].endPoint = new IPEndPoint(address, localPort);

                    // start unicast reciever on main interface
                    interfacesListerner[i].thread = new Thread(unicastReciever);
                    interfacesListerner[i].thread.IsBackground = true;

                    interfacesListerner[i].inUse = true;

                    traceWriteLine(debugLevel.Info, String.Format("Listening on {0}...", interfacesListerner[i].endPoint.ToString()), interfacesListerner[i].thread.ManagedThreadId);
                }
                catch
                {
                    interfacesListerner[i].inUse = false;
                }
                interfacesListerner[i].thread.Start();
            }

            return;
        }

        public bool listenMulticast(IPAddress multicastIP, int multicastPort)
        {
            this.multicastIP = multicastIP;
            this.multicastPort = multicastPort;

            try
            {
                multicastListener.inUse = true;
                multicastListener.thread = new Thread(multicastReciever);
                multicastListener.thread.IsBackground = true;
                multicastListener.thread.Start();
            }
            catch
            {
                multicastListener.inUse = false;
                return false;
            }

            return true;
        }

        public abstract byte[] sender(IPEndPoint dest);
        public abstract void reciever(IPEndPoint from, byte[] data);

        public void registerViewer(ScannerViewer viewer)
        {
            this.viewer = viewer;
            viewer.scanEvent += this.scan;
            viewer.formatProtocol(name, color);
        }

        public bool send(IPEndPoint endpoint)
        {
            byte[] data;

            if (interfacesListerner == null && !globalListener.inUse)
            {
                traceWriteLine(debugLevel.Fatal, "Error: send(): no opened sockets, you must call listenUdpInterfaces() or listenUdpGlobal() before.");
                throw new InvalidOperationException("No opened sockets");
                //return false;
            }

            data = sender(endpoint);

            if (globalListener.inUse)
            {
                traceWriteLine(debugLevel.Info, String.Format("{0} -> {1}", globalListener.endPoint.ToString(), endpoint.ToString()));
                traceWriteData(debugLevel.Debug, data);
                try
                {
                    globalListener.udp.Send(data, data.Length, endpoint);
                }
                catch { }
            }

            if (interfacesListerner != null)
            {
                foreach (networkBundle net in interfacesListerner)
                {
                    if (net.inUse)
                    {
                        traceWriteLine(debugLevel.Info, String.Format("{0} -> {1}", net.endPoint.ToString(), endpoint.ToString()));
                        traceWriteData(debugLevel.Debug, data);
                        try
                        {
                            net.udp.Send(data, data.Length, endpoint);
                        }
                        catch { }
                    } }
            }
            return true;
        }

        public bool sendBroadcast(int port)
        {
            return send(new IPEndPoint(IPAddress.Broadcast, port));
        }

        public bool sendMulticast(IPAddress dest, int port)
        {
            return send(new IPEndPoint(dest, port));
        }

        public bool sendUnicast(IPAddress dest, int port)
        {
            return send(new IPEndPoint(dest, port));
        }

        public bool sendNetScan(int port)
        {
            if (scannerThread != null)
            {
                scannerThread.Abort();
            }

            if (!globalListener.inUse && interfacesListerner == null)
            {
                traceWriteLine(debugLevel.Fatal, "Error: sendNetScan(): no opened sockets, you must call listenUdpInterfaces() or listenUdpGlobal() before.");
                throw new InvalidOperationException("No opened sockets");
                //return false;
            }
            scannerPort = port;

            if (globalListener.inUse)
            {
                scannerThread = new Thread(sendNetScannerGlobal);
            }
            else
            {
                scannerThread = new Thread(sendNetScannerInterfaces);
            }

            scannerThread.IsBackground = true;
            scannerThread.Start();

            return true;
        }

        private void sendNetScannerGlobal()
        {
            List<IPAddress> addresses;
            byte[] data;

            addresses = new List<IPAddress>();
            foreach (var iface in listActiveInterface())
            {
                addresses.AddRange(listInterfaceAddresses(iface, AddressFamily.InterNetwork));
            }

            foreach (var net in addresses)
            {
                if (isPrivateIPv4Network(net))
                {
                    IPAddress mask = getMaskOfAddressIPv4(net);
                    IPAddress[] subNetAddresses;

                    subNetAddresses = subNetListIPv4Addresses(net, mask, 254);
                    foreach (IPAddress local in subNetAddresses)
                    {
                        IPEndPoint endpoint = new IPEndPoint(local, scannerPort);
                        data = sender(endpoint);

                        traceWriteLine(debugLevel.Info, string.Format("{0} -> {1}", globalListener.endPoint.ToString(), endpoint.ToString()));
                        traceWriteData(debugLevel.Debug, data);

                        try
                        {
                            globalListener.udp.Send(data, data.Length, endpoint);
                        }
                        catch { }
                    }
                }
            }
        }

        private void sendNetScannerInterfaces()
        {
            byte[] data;

            foreach (networkBundle net in interfacesListerner)
            {
                if (net.inUse && isPrivateIPv4Network(net.endPoint.Address))
                {
                    IPAddress mask = getMaskOfAddressIPv4(net.endPoint.Address);
                    IPAddress[] subNetAddresses;

                    subNetAddresses = subNetListIPv4Addresses(net.endPoint.Address, mask, 254);

                    foreach (IPAddress local in subNetAddresses)
                    {
                        if (local.Equals(net.endPoint.Address))
                            continue;

                        IPEndPoint endpoint = new IPEndPoint(local, scannerPort);
                        data = sender(endpoint);

                        traceWriteLine(debugLevel.Fatal, String.Format("{0} -> {1}", net.endPoint.ToString(), endpoint.ToString()));
                        traceWriteData(debugLevel.Debug, data);

                        try
                        {
                            net.udp.Send(data, data.Length, endpoint);
                        }
                        catch { }
                    }
                }
            }
        }

        public void selfTest(string filename=null)
        {
            if (filename == null)
            {
                filename = String.Format("{0}.selftest", name);
            }

            if (File.Exists(filename))
            {
                try
                {
                    var content = File.ReadAllBytes(filename);
                    reciever(new IPEndPoint(IPAddress.Loopback, 1024), content);
                }
                catch (Exception e)
                {
                    traceWriteLine(debugLevel.Debug, String.Format("selfTest(): Error while performing self test for protocol {0}", name));
                    traceWriteLine(debugLevel.Debug, e.ToString());
                }
            }
            else
            {
                traceWriteLine(debugLevel.Debug, String.Format("selfTest(): Self test file not found for protocol {1}: '{0}' is missing", name, filename));
            }
        }

        protected bool isFreeUdpPort(int localPort)
        {
            IEnumerable<int> portsInUse;

            portsInUse =
                from used in IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners()
                where used.Port == localPort
                select used.Port;

            return (portsInUse.Count() == 0);
        }

        protected int getFreeUdpPort()
        {
            int[] portRange = { 1024, 65534 };
            IEnumerable<int> portsUseable, portsInUse, portsFree;
            int countFree;
            Random rand;

            portsUseable = Enumerable.Range(portRange[0], portRange[1] - portRange[0]);
            portsInUse =
                from p in portsUseable
                join used in IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners()
            on p equals used.Port
                select p;

            portsFree = portsUseable.Except(portsInUse);

            countFree = portsFree.Count();
            if (countFree == 0)
            {
                traceWriteLine(debugLevel.Fatal, "Error: UdpFreePortProvider(): No free UDP port!");
                throw new OverflowException();
            }

            rand = new Random();
            int index = rand.Next(0, countFree);

            return portsFree.ElementAt(index);
        }

        protected NetworkInterface[] listActiveInterface()
        {
            var interfaceList =
                from iface in NetworkInterface.GetAllNetworkInterfaces()
                where iface.OperationalStatus == OperationalStatus.Up
                select iface;

            return interfaceList.Cast<NetworkInterface>().ToArray();
        }

        protected IPAddress[] listInterfaceAddresses(NetworkInterface iface, AddressFamily adressType)
        {
            var addressList =
                from addr in iface.GetIPProperties().UnicastAddresses
                where (addr.Address.AddressFamily == adressType)
                select addr.Address;

            return addressList.Cast<IPAddress>().ToArray();
        }

        protected IPAddress getMaskOfAddressIPv4(IPAddress address)
        {
            var masks = (from iface in NetworkInterface.GetAllNetworkInterfaces()
                         where iface.OperationalStatus == OperationalStatus.Up
                         select iface.GetIPProperties() into ifaceProp
                         from addr in ifaceProp.UnicastAddresses
                         where (addr.Address.AddressFamily == AddressFamily.InterNetwork && addr.Address.Equals(address))
                         select addr.IPv4Mask);

            if (masks.Count() == 1)
            {
                return masks.First();
            }

            return IPAddress.Parse("255.255.255.255");
        }

        protected IPAddress[] subNetListIPv4Addresses(IPAddress address, IPAddress subNetMask, UInt32 maxLen)
        {
            UInt32 addr, mask, first, last, len, i, current;
            IPAddress[] result;

            addr = ntohl(BitConverter.ToUInt32(address.GetAddressBytes(), 0));
            mask = ntohl(BitConverter.ToUInt32(subNetMask.GetAddressBytes(), 0));

            first = (addr & mask) + 1;
            last = (addr | ~mask) - 1;

            len = last - first + 1;
            if (len > maxLen)
            {
                len = maxLen;
            }
            result = new IPAddress[len];
            for (i = 0; i < len; i++)
            {
                current = first + i;

                result[i] = new IPAddress(
                BitConverter.ToUInt32(new byte[] { (byte)(current >> 24), (byte)(current >> 16), (byte)(current >> 8), (byte)current }, 0));
            }

            return result;
        }

        protected bool isPrivateIPv4Network(IPAddress address)
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

        private void unicastReciever()
        {
            byte[] data;
            UdpClient unicastUDP;
            IPEndPoint localEP;

            if (Thread.CurrentThread == globalListener.thread)
            {
                unicastUDP = globalListener.udp;
                localEP = globalListener.endPoint;
            }
            else
            {
                unicastUDP =
                    (from thread in interfacesListerner
                     where thread.thread == Thread.CurrentThread
                     select thread.udp).First();
                localEP =
                    (from thread in interfacesListerner
                     where thread.thread == Thread.CurrentThread
                     select thread.endPoint).First();
            }

            try
            {
                unicastUDP.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                unicastUDP.Client.Bind(localEP);
            }
            catch

            {
                traceWriteLine(debugLevel.Error, String.Format("Error: ScanEngine.unicastReciever(): Unable to bind {0}!", localEP.ToString()));
                return;
            }

            while (!closing)
            {
                IPEndPoint distantEP;

                distantEP = null;
                try
                {
                    data = unicastUDP.Receive(ref distantEP);

                    traceWriteLine(debugLevel.Info, String.Format("{0} <- {1}", localEP.ToString(), distantEP.ToString()));
                    traceWriteData(debugLevel.Debug, data);

                    reciever(distantEP, data);
                }
                catch
                { }
            }
        }

        /* multicast listener */
        private void multicastReciever()
        {
            byte[] data;
            List<MulticastOption> multicastOption;

            multicastOption = new List<MulticastOption>();

            multicastListener.udp = new UdpClient();
            multicastListener.endPoint = new IPEndPoint(IPAddress.Any, multicastPort);
            foreach (var iface in listActiveInterface())
            {
                IPAddress[] ifaceAddrs;

                ifaceAddrs = listInterfaceAddresses(iface, AddressFamily.InterNetwork);
                if (ifaceAddrs.Length > 0)
                {
                    multicastOption.Add(new MulticastOption(multicastIP, ifaceAddrs[0]));
                }
            }

            try
            {
                multicastListener.udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            }
            catch (Exception ex)
            {
                traceWriteLine(debugLevel.Error, String.Format("Error: multicastReciever(): Unable to enable option ReuseAddress for socket {0}!", multicastListener.endPoint.ToString()));
                traceWriteLine(debugLevel.Error, String.Format("Error: multicastReciever(): {0}", ex.ToString()));
            }

            foreach (var opt in multicastOption)
            {
                traceWriteLine(debugLevel.Info, String.Format("Joining group {0} on interface {1}", opt.Group.ToString(), opt.LocalAddress.ToString()));
                try
                {
                    multicastListener.udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, opt);
                }
                catch (Exception ex)
                {
                    traceWriteLine(debugLevel.Error, String.Format("Error: multicastReciever(): Unable to join group {0} on interface {1}!", opt.Group.ToString(), opt.LocalAddress.ToString()));
                    traceWriteLine(debugLevel.Error, String.Format("Error: multicastReciever(): {0}", ex.ToString()));
                }
            }

            try
            {
                multicastListener.udp.Client.Bind(multicastListener.endPoint);
            }
            catch (Exception ex)
            {
                traceWriteLine(debugLevel.Error, String.Format("Error: multicastReciever(): Unable to bind {0}!", multicastListener.endPoint.ToString()));
                traceWriteLine(debugLevel.Error, String.Format("Error: multicastReciever(): {0}", ex.ToString()));
                return;
            }

            while (!closing)
            {
                IPEndPoint distantEP;

                distantEP = null;
                try
                {
                    data = multicastListener.udp.Receive(ref distantEP);

                    traceWriteLine(debugLevel.Info, String.Format("{0} <- {1}", multicastListener.endPoint.ToString(), distantEP.ToString()));
                    traceWriteData(debugLevel.Debug, data);

                    reciever(distantEP, data);
                }
                catch { }
            }
            foreach (var opt in multicastOption)
            {
                try
                {
                    traceWriteLine(debugLevel.Info, String.Format("Leaving group {0} on interface {1}", opt.Group.ToString(), opt.LocalAddress.ToString()));
                    multicastListener.udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.DropMembership, opt);
                }
                catch { }
            }
            try
            {
                multicastListener.udp.Close();
            }
            catch {}
        }

        public void Dispose()
        {
            if (isDisposed)
                return;

            closing = true;

            if (globalListener.inUse)
            {
                globalListener.thread.Abort();
            }
            if (multicastListener.inUse)
            {
                multicastListener.thread.Abort();
            }
            if (interfacesListerner != null)
            {
                foreach (networkBundle net in interfacesListerner)
                {
                    if (net.inUse)
                    {
                        net.thread.Abort();
                    }
                }
            }
            isDisposed = true;
        }

        ~ScanEngine()
        {
            this.Dispose();
        }
    }
}
