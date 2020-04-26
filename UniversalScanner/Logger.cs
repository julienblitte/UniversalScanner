using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UniversalScanner
{
    public static class Logger
    {
        public enum DebugLevel { Fatal = 0, Error = 1, Warn = 2, Info = 3, Debug = 4 };

        public static DebugLevel level;

        static Logger()
        {
#if DEBUG
            level = DebugLevel.Debug;
#else
            level  = DebugLevel.Info;
#endif
        }

        public static void WriteData(DebugLevel dataLevel, byte[] data, int threadId = 0)
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

        public static void WriteLine(DebugLevel lineLevel, string line, int threadId = 0)
        {
            if (threadId == 0)
            {
                threadId = Thread.CurrentThread.ManagedThreadId;
            }

            Trace.WriteLineIf(lineLevel <= level, String.Format("[{0,4}] {1}", threadId, line));
        }


    }
}
