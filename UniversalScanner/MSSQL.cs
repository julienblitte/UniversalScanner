using System;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

/*
 * @description: UniversalScanner discovery protocol
 */

namespace UniversalScanner
{
    class MSSQL : ScanEngine
    {
        private const int port = 1434;

        public enum datagramType : byte
        {
            request = 2,
            response = 5
        };

        public override int color
        {
            get
            {
                return Color.Black.ToArgb();
            }
        }
        public override string name
        {
            get
            {
                return "MSSQL";
            }
        }
        public MSSQL()
        {
            listenUdpGlobal(port);
            listenUdpInterfaces();
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
            byte[] result;

            result = new byte[1];
            result[0] = (byte)datagramType.request;

            return result;
        }

        public override void reciever(IPEndPoint from, byte[] data)
        {
            byte len;
            string textPayload;
            string[] arrayPayload;
            string deviceModel, deviceSerial;
            Dictionary<string, string> variables;

            if (data.Length < 3)
                return;

            if (data[0] != (byte)datagramType.response)
            {
                return;
            }

            len = data[1];

            if (len != data.Length - 3)
            {
                Logger.getInstance().WriteLine(Logger.DebugLevel.Warn, String.Format("Warning: MSSQL.reciever(): Invalid packet length (got value 0x{0:X8} while data size is 0x{1:X8}) recieved from {2}",
                    len, data.Length - 3, from));
                return;
            }

            textPayload = Encoding.UTF8.GetString(data, 3, data.Length - 3);
            arrayPayload = textPayload.Split(';');

            variables = new Dictionary<string, string>();
            int i = 0;
            while (i < arrayPayload.Length - 1)
            {
                // second instance
                if (arrayPayload[i] == "")
                {
                    i++;
                    // we don't want to list all instances, keep only the first one
                    break;
                }
                variables.Add(arrayPayload[i], arrayPayload[i + 1]);
                i += 2;
            }

            // Version

            deviceModel = "Unknown";
            if (variables.ContainsKey("InstanceName"))
            {
                deviceModel = variables["InstanceName"];
            }

            deviceSerial = "Unknown";
            if (variables.ContainsKey("ServerName"))
            {
                deviceSerial = variables["ServerName"];
            }

            viewer.deviceFound(name, 1, from.Address, deviceModel, deviceSerial);
        }

    }
}

