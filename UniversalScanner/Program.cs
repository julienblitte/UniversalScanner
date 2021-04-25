using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UniversalScanner
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            ScannerWindow viewer;
            ScanEngine[] engines;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            viewer = new ScannerWindow();          

            engines = new ScanEngine[] {
                new UPnP(),
                new Wsdiscovery(),
                new Dahua1(),
                new Dahua2(),
                new Hikvision(),
                new Axis(),
                new Bosch(),
                new GoogleCast(),
                new Hanwha(),
                new Vivotek(),
                new Sony(),
                new Ubiquiti(),
                new _360Vision(),
                new NiceVision(),
                new Panasonic(),
                new Arecont(),
                new GigEVision(),
                new Vstarcam(),
                new Eaton(),
                //new Foscam(),
                //new Dlink(),
                //new Hid(),
                //new Lantronix(),
                //new GCE()
                // further protocol 25
                // further protocol 26
                // further protocol 27
                // further protocol 28
                // further protocol 29
                // further protocol 30
                // further protocol 31
                // further protocol 32
                // further protocol 33
                // further protocol 34
                // further protocol 35
                // further protocol 36
                // further protocol 37
                // further protocol 38
                // further protocol 39
                // further protocol 40
                // further protocol 41
                // further protocol 42
                // further protocol 43
                // further protocol 44
                // further protocol 45
                // further protocol 46
                // further protocol 47
                // further protocol 48
                // further protocol 49
                // further protocol 50
            };
            foreach(var engine in engines)
            {
                engine.registerViewer(viewer);
            }

            Application.Run(viewer);
        }
    }
}
