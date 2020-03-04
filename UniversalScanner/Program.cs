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
            Dahua1 engineDahua1;
            Dahua2 engineDahua2;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            viewer = new ScannerWindow();
            engineDahua1 = new Dahua1();
            engineDahua2 = new Dahua2();
            // engineDahua1 decides if engineDahua2 use quirk mode or not
            engineDahua2.quirk = engineDahua1.quirk;
            engines = new ScanEngine[] {
                new UPnP(),
                engineDahua1,
                engineDahua2,
                new Hikvision(),
				new Bosch()
            };
            foreach(var engine in engines)
            {
                engine.registerViewer(viewer);
            }

            Application.Run(viewer);

        }
    }
}
