﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using JulienBlitte;

namespace UniversalScanner
{
    public delegate void scan();
    public interface ScannerViewer
    {
        void deviceFound(string protocol, int version, IPAddress deviceIP, string deviceType, string serial);
        event scan scanEvent;
        void formatProtocol(string protocol, int color);
    }

    public abstract class ScanEngine : IDisposable
    {
        private IPAddress multicastIP;
        private int multicastPort = 0;

        private Thread scannerThread = null;
        private int scannerPort = 0;

        protected ScannerViewer viewer = null;

        protected bool closing = false;
        public bool isDisposed = false;

        protected uint id;

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

        public ScanEngine()
        {
            globalListener.inUse = false;
            multicastListener.inUse = false;
        }

        public abstract UInt16[] getUsedPort();

        public abstract void listen();
        public abstract void scan();

        public int listenUdpGlobal(int localPort = 0)
        {
            bool reuseAddress = false;

            if (localPort != 0)
            {
                if (!isFreeUdpPort(localPort))
                {
                    Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: ScanEngine.listenUdpGlobal(): Local UDP port {0} is already in use...", localPort));
                    if (Config.getInstance().PortSharing)
                    {
                        Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: ScanEngine.listenUdpGlobal(): Trying to share the port {0}...", localPort));
                        reuseAddress = true;
                    }
                    else
                    {
                        return -1;
                    }
                }
            }
            else
            {
                localPort = PortProvider.getInstance().getFreeUdpPort();
            }

            try
            {
                /* configure UdpClient and EndPoint */
                globalListener.udp = new UdpClient();
                globalListener.udp.EnableBroadcast = true;
                globalListener.endPoint = new IPEndPoint(IPAddress.Any, localPort);

                if (reuseAddress)
                {
                    globalListener.udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                }

                // start unicast reciever on main interface
                globalListener.thread = new Thread(unicastReciever);
                globalListener.thread.IsBackground = true;

                globalListener.inUse = true;

               Logger.getInstance().WriteLine(Logger.DebugLevel.Info, String.Format("Listening on {0}...", globalListener.endPoint.ToString()), globalListener.thread.ManagedThreadId);
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
                int localPort = PortProvider.getInstance().getFreeUdpPort();
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

                   Logger.getInstance().WriteLine(Logger.DebugLevel.Info, String.Format("Listening on {0}...", interfacesListerner[i].endPoint.ToString()), interfacesListerner[i].thread.ManagedThreadId);
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

        public void registerViewer(ScannerViewer viewer, uint id=0)
        {
            this.viewer = viewer;
            viewer.scanEvent += this.scan;
            viewer.formatProtocol(name, color);

            this.id = id;
        }

        public bool send(IPEndPoint endpoint)
        {
            byte[] data;

            if (interfacesListerner == null && !globalListener.inUse && !multicastListener.inUse)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Fatal, "Error: sendNetScan(): no opened sockets, you must call listenUdpInterfaces(), listenUdpGlobal() or listenMulticast() before.");
                throw new InvalidOperationException("No opened sockets");
                //return false;
            }

            data = sender(endpoint);

            if (multicastListener.inUse)
            {
                Logger.getInstance().WriteNet(Logger.DebugLevel.Debug, multicastListener.endPoint, endpoint, ProtocolType.Udp, data);
                try
                {
                    multicastListener.udp.Send(data, data.Length, endpoint);
                }
                catch { }
            }

            if (globalListener.inUse)
            {
                Logger.getInstance().WriteNet(Logger.DebugLevel.Debug, globalListener.endPoint, endpoint, ProtocolType.Udp, data);
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
                        Logger.getInstance().WriteNet(Logger.DebugLevel.Debug, net.endPoint, endpoint, ProtocolType.Udp, data);
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
               Logger.getInstance().WriteLine(Logger.DebugLevel.Fatal, "Error: sendNetScan(): no opened sockets, you must call listenUdpInterfaces() or listenUdpGlobal() before.");
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
                if (net.isPrivate())
                {
                    IPAddress mask = getMaskOfAddressIPv4(net);
                    IPAddress[] subNetAddresses;

                    subNetAddresses = subNetListIPv4Addresses(net, mask, 254);
                    foreach (IPAddress local in subNetAddresses)
                    {
                        IPEndPoint endpoint = new IPEndPoint(local, scannerPort);
                        data = sender(endpoint);

                        Logger.getInstance().WriteNet(Logger.DebugLevel.Debug, globalListener.endPoint, endpoint, ProtocolType.Udp, data);

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
                if (net.inUse && net.endPoint.Address.isPrivate())
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

                        Logger.getInstance().WriteNet(Logger.DebugLevel.Debug, net.endPoint, endpoint, ProtocolType.Udp, data);

                        try
                        {
                            net.udp.Send(data, data.Length, endpoint);
                        }
                        catch { }
                    }
                }
            }
        }

        public void selfTest(string filename=null, uint minor=0)
        {
            IPAddress source;

            if (filename == null)
            {
                filename = String.Format("{0}.selftest", name);
            }

            if (File.Exists(filename))
            {
                if (filename.Length > 2)
                {
                    
                    source = new IPAddress(new byte[] { 240, 0, (byte)(id & 0xff), (byte)(minor) });
                }
                else
                {
                    source = IPAddress.Loopback;
                }

                try
                {
                    var content = File.ReadAllBytes(filename);
                    var endpoint = new IPEndPoint(source, 1024);

                    Logger.getInstance().WriteNet(Logger.DebugLevel.Debug, endpoint, endpoint, ProtocolType.Udp, content);
                    reciever(endpoint, content);
                }
                catch (Exception e)
                {
                   Logger.getInstance().WriteLine(Logger.DebugLevel.Debug, String.Format("Error while performing self test for protocol {0}", name));
                   Logger.getInstance().WriteLine(Logger.DebugLevel.Debug, e.ToString());
                }
            }
            else
            {
               Logger.getInstance().WriteLine(Logger.DebugLevel.Debug, String.Format("Warning: Self test file not found for protocol {0}: '{1}' is missing", name, filename));
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

            addr = address.ToUInt32();
            mask = subNetMask.ToUInt32();

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

                result[i] = new IPAddress(NetworkUtils.HostToNetworkOrder32(current));
            }

            return result;
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
            catch (Exception e)
            {
               Logger.getInstance().WriteLine(Logger.DebugLevel.Error, String.Format("Error: ScanEngine.unicastReciever(): Unable to bind {0}!", localEP.ToString()));
               Logger.getInstance().WriteLine(Logger.DebugLevel.Error, e.ToString());
               return;
            }

            while (!closing)
            {
                IPEndPoint distantEP;

                distantEP = null;
                try
                {
                    data = unicastUDP.Receive(ref distantEP);

                    Logger.getInstance().WriteNet(Logger.DebugLevel.Debug, distantEP, localEP, ProtocolType.Udp, data);

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
               Logger.getInstance().WriteLine(Logger.DebugLevel.Error, String.Format("Error: multicastReciever(): Unable to enable option ReuseAddress for socket {0}!", multicastListener.endPoint.ToString()));
               Logger.getInstance().WriteLine(Logger.DebugLevel.Error, String.Format("Error: multicastReciever(): {0}", ex.ToString()));
            }

            foreach (var opt in multicastOption)
            {
               Logger.getInstance().WriteLine(Logger.DebugLevel.Info, String.Format("Joining group {0} on interface {1}", opt.Group.ToString(), opt.LocalAddress.ToString()));
                try
                {
                    multicastListener.udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, opt);
                }
                catch (Exception ex)
                {
                   Logger.getInstance().WriteLine(Logger.DebugLevel.Error, String.Format("Error: multicastReciever(): Unable to join group {0} on interface {1}!", opt.Group.ToString(), opt.LocalAddress.ToString()));
                   Logger.getInstance().WriteLine(Logger.DebugLevel.Error, String.Format("Error: multicastReciever(): {0}", ex.ToString()));
                }
            }

            try
            {
                multicastListener.udp.Client.Bind(multicastListener.endPoint);
            }
            catch (Exception ex)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Error, String.Format("Error: multicastReciever(): Unable to bind {0}!", multicastListener.endPoint.ToString()));
                Logger.getInstance().WriteLine(Logger.DebugLevel.Error, String.Format("Error: multicastReciever(): {0}", ex.ToString()));
                return;
            }

            while (!closing)
            {
                IPEndPoint distantEP;

                distantEP = null;
                try
                {
                    data = multicastListener.udp.Receive(ref distantEP);

                    Logger.getInstance().WriteNet(Logger.DebugLevel.Debug, distantEP, multicastListener.endPoint, ProtocolType.Udp, data);

                    reciever(distantEP, data);
                }
                catch { }
            }
            foreach (var opt in multicastOption)
            {
                try
                {
                    Logger.getInstance().WriteLine(Logger.DebugLevel.Info, String.Format("Leaving group {0} on interface {1}", opt.Group.ToString(), opt.LocalAddress.ToString()));
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
