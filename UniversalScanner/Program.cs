using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UniversalScanner
{
    static class Program
    {

        [DllImport("user32.dll")]
        public static extern bool ShowWindowAsync(HandleRef hWnd, int nCmdShow);
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr WindowHandle);
        public const int SW_RESTORE = 9;

        static bool checkAlreadyRunning(bool foregroundExisting = false)
        {
            Process[] running;
            
            running = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(Assembly.GetEntryAssembly().Location));
            
            if (running.Length <= 1)
            {
                return false;
            }
            else if (!foregroundExisting)
            {
                return true;
            }

            foreach(Process p in running)
            {
                IntPtr hWnd = IntPtr.Zero;
                hWnd = p.MainWindowHandle;
                if (hWnd != IntPtr.Zero)
                {
                    ShowWindowAsync(new HandleRef(null, hWnd), SW_RESTORE);
                    SetForegroundWindow(p.MainWindowHandle);
                }
            }

            return true;
        }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            ScannerWindow viewer;
            ScanEngine[] engines;

            if (checkAlreadyRunning(true))
            {
                Application.Exit();
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            viewer = new ScannerWindow();          

            engines = new ScanEngine[] {
                new SSDP(),         //  1
                new Wsdiscovery(),  //  2
                new Dahua1(),       //  3
                new Dahua2(),       //  4
                new Hikvision(),    //  5
                new Axis(),         //  6
                new Bosch(),        //  7
                new GoogleCast(),   //  8
                new Hanwha(),       //  9
                new Vivotek(),      // 10
                new Sony(),         // 11
                new Ubiquiti(),     // 12
                new _360Vision(),   // 13
                new NiceVision(),   // 14
                new Panasonic(),    // 15
                new Arecont(),      // 16
                new GigEVision(),   // 17
                new Vstarcam(),     // 18
                new Eaton(),        // 19
                null, //new Foscam(),     // 20
                null, //new Dlink(),      // 21
                null, //new Hid(),        // 22
                new Lantronix(),    // 23
                new Microchip(),    // 24
                new Advantech(),    // 25
                new EdenOptima(),   // 26
                null,  //new Microsens()   // 27
                new CyberPower()        // 28
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
            for (uint i= 0; i < engines.Length; i++)
            {
                if (engines[i] != null)
                {
                    engines[i].registerViewer(viewer, i + 1);
                }
            }

            Application.Run(viewer);
        }
    }
}
