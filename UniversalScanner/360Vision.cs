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
    class _360Vision : ScanEngine
    {
        protected int port = 3600;

        private string request = "DISCOVER\n";

        public override string name
        {
            get
            {
                return "360Vision";
            }
        }
        public override int color
        {
            get
            {
                return Color.Purple.ToArgb();
            }
        }

        public _360Vision()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
        }

        Dictionary<string, string> readKeyValuePairs(string data)
        {
            Dictionary<string, string> result;
            Regex keyValuePair;

            result = new Dictionary<string, string>();

            keyValuePair = new Regex("([a-zA-Z_][a-zA-Z0-9_]*)=('[^']*'|\"[^\"]*\"|[^ ]*)");
            var m = keyValuePair.Matches(data);

            for (int i = 0; i < m.Count; i++)
            {
                string key, value;

                key = m[i].Groups[1].Value;
                value = m[i].Groups[2].Value;

                if (value.Length >= 2)
                {
                    int len = value.Length;

                    if (value[0] == '\'' && value[len - 1] == '\'')
                    {
                        value = value.Substring(1, len - 2);
                    }
                    else if (value[0] == '"' && value[len - 1] == '"')
                    {
                        value = value.Substring(1, len - 2);
                    }
                }
                result.Add(key, value);
            }

            return result;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            string text;
            string type;
            string serial;

            int EOS;

            text = Encoding.UTF8.GetString(data);
            if (text == request)
            {
                // loopback, ignore
                return;
            }

            EOS = text.IndexOf('\n');

            if (EOS > 0)
            {
                text = text.Substring(0, EOS - 1);
            }

            var r = readKeyValuePairs(text);

            type = "Unknown";
            if (r.ContainsKey("TYPE"))
            {
                type = r["TYPE"];
            }

            serial = "Unknown";
            if (r.ContainsKey("KEY"))
            {
                serial = r["KEY"];
            }

            viewer.deviceFound(name, 1, from.Address, type, serial);
        }

        public override void scan()
        {
#if DEBUG
            selfTest();
#endif
            sendBroadcast(port);
        }

        public override byte[] sender(IPEndPoint dest)
        {
            return Encoding.UTF8.GetBytes(request);
        }
    }
}
