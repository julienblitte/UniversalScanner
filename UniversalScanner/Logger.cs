using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using JulienBlitte;

namespace UniversalScanner
{
    public class Logger : IDisposable
    {
        public enum DebugLevel { Fatal = 0, Error = 1, Warn = 2, Info = 3, Debug = 4 };

        private static DebugLevel level;
        private static Logger instance;
        private PcapFile pcap;
        private UInt32 packetCounter;

        private Logger()
        {
#if DEBUG
            level = DebugLevel.Debug;
            openPcap();
#else
            level  = DebugLevel.Info;
#endif
        }

        private void openPcap()
        {
            pcap = new PcapFile("UniversalScanner_" + DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss") + ".pcap");
            packetCounter = 0;
        }

        public static Logger getInstance()
        {
            if (instance == null)
            {
                instance = new Logger();
            }
            return instance;
        }

        public void setLevel(DebugLevel level)
        {
            Logger.level = level;

            if (level == DebugLevel.Debug && pcap == null)
            {
                openPcap();
            }
        }

        public void WriteNet(DebugLevel dataLevel, IPEndPoint source, IPEndPoint destination, ProtocolType protocol, byte[] payload)
        {
            if (dataLevel > level)
            {
                return;
            }

            if (pcap != null)
            {
                pcap.Append(source, destination, protocol, payload);
                packetCounter++;
                WriteLine(DebugLevel.Debug, String.Format("Packet {0}", packetCounter));
            }
        }

        public void WriteData(DebugLevel dataLevel, byte[] data, int threadId = 0)
        {
            string textFromData;
            bool isBinary;
            string[] lines;
            StringBuilder result;
            Regex binaryCharacters;

            if (dataLevel > level)
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

            Trace.WriteLineIf(dataLevel <= level, String.Format("[{0,4}] {1}", threadId, result.ToString()));
        }

        public void WriteLine(DebugLevel lineLevel, string line, int threadId = 0)
        {
            if (threadId == 0)
            {
                threadId = Thread.CurrentThread.ManagedThreadId;
            }

            Trace.WriteLineIf(lineLevel <= level, String.Format("[{0,4}] {1}", threadId, line));
        }

        public void Dispose()
        {
            if (pcap != null && packetCounter > 0)
            {
                pcap.Save();
            }
        }
    }
}
