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
            mDNS engineMDNS;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            viewer = new ScannerWindow();
            // Dahua1 and Dahua2 must be started together because of quirk mode
            engineDahua1 = new Dahua1();
            engineDahua2 = new Dahua2();
            // if Dahua1 is quirk mode, switch Dahua2 to quirk mode
            engineDahua2.quirk = engineDahua1.quirk;
            //engineMDNS must be started before as it is used by other engine using mDNS
            engineMDNS = new mDNS();
            

            engines = new ScanEngine[] {
                new UPnP(),
                engineDahua1,
                engineDahua2,
                new Hikvision(),
                new Axis(engineMDNS),
                new Bosch(),
                new GoogleCast(engineMDNS),
                new Hanwha(),
                new Sony()
            };
            foreach(var engine in engines)
            {
                engine.registerViewer(viewer);
            }

            Application.Run(viewer);
        }
    }
}
