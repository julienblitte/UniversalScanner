using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using JulienBlitte;

namespace selftest2pcap
{
    class Program
    {

        static void usage()
        {
            Console.WriteLine("Convert a selftest file into pcap file");
            Console.WriteLine(String.Format("Usage: {0} <input.selftest> <output.pcap> [udp.destport]", "selftest2pcap"));
        }

        static void Main(string[] args)
        {
            PcapFile destPcap;
            UInt16 destPort;
            DateTime captureTime;
            byte[] payload;

            string source, dest;

            if (args.Length < 2)
            {
                usage();
                return;
            }

            if (args.Length > 2)
            {
                if (!UInt16.TryParse(args[2], out destPort))
                {
                    Console.WriteLine(String.Format("Error: The value {0} is not a valid port number!", args[2]));
                    usage();
                    return;
                }
            }
            else
            {
                destPort = 1024;
            }

            source = args[0];
            dest = args[1];



            if (!File.Exists(source))
            {
                Console.WriteLine(String.Format("Error: File {0} does not exists!", source));
            }
            if (File.Exists(dest))
            {
                Console.WriteLine(String.Format("Error: File {0} already exists! Please delete it first.", dest));
            }

            try
            {
                /* load payload */
                payload = File.ReadAllBytes(source);
                captureTime = File.GetLastWriteTimeUtc(source);

                destPcap = new PcapFile(dest);
                destPcap.Append(new IPEndPoint(IPAddress.Loopback, 1024), new IPEndPoint(IPAddress.Loopback, destPort), ProtocolType.Udp, payload, captureTime);

                destPcap.Save();
            }
            catch (Exception e)
            {
                Console.WriteLine(String.Format("Error: Unable to convert '{0}' to '{1}'!", source, dest));
                Console.WriteLine(e.ToString());
                return;
            }

            Console.WriteLine(String.Format("'{0}' -> '{1}'", source, dest));
        }
    }
}
