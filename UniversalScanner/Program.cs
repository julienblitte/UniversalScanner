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
                new Ubiquiti()
            };
            foreach(var engine in engines)
            {
                engine.registerViewer(viewer);
            }

            Application.Run(viewer);
        }
    }
}
