using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;
using System.Collections;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using UniversalScannerLib;

namespace UniversalScannerUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, ScannerViewer
    {
        public event scan scanEvent;

        private Dictionary<string, int> protocolFormat = new Dictionary<string, int>();

        public static void RegisterScanning(ScannerViewer viewer)
        {
            ScanEngine[] engines;

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
                new _360Vision()
            };

            foreach (var engine in engines)
            {
                engine.registerViewer(viewer);
            }
        }

        public MainWindow()
        {
            InitializeComponent();

            this.Loaded += MainWindow_Loaded;
            scanButton.Click += scanButton_Click;
            aboutButton.Click += aboutButton_Click;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
#if DEBUG
            var versionInfo = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location);
            this.Title += " - debug " + versionInfo.Comments;
#endif

            // Set scan values
            RegisterScanning(this);
        }
        
        public void deviceFound(string protocol, int version, IPAddress deviceIP, string deviceType, string deviceUUID)
        {
            if (!this.IsVisible)
                return;

            if (deviceIP.AddressFamily == AddressFamily.InterNetwork && !Config.enableIPv4)
                return;

            if (deviceIP.AddressFamily == AddressFamily.InterNetworkV6 && !Config.enableIPv6)
                return;

            lstFoundDevice.Dispatcher.Invoke(() =>
            {
                string dev = $"{deviceIP} | {protocol} | {version} | {deviceType} | {deviceUUID}";
                lstFoundDevice.Items.Add(dev);
            });
        }

        private void scanButton_Click(object sender, RoutedEventArgs e)
        {
            lstFoundDevice.Items.Clear();
            scanEvent.Invoke();
        }

        private void aboutButton_Click(object sender, RoutedEventArgs e)
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location);

            MessageBox.Show(this,
                String.Format("{0} {1}.{2}\nBuild date {3:0000}-{4:00}-{5:00}\n\nCopyright {6}\n\n{7}",
                    versionInfo.ProductName, versionInfo.FileMajorPart, versionInfo.FileMinorPart,
                    versionInfo.ProductBuildPart, (versionInfo.ProductPrivatePart / 100), (versionInfo.ProductPrivatePart % 100),
                    versionInfo.LegalCopyright,
                    "Program under GNU Lesser General Public License 3.0,\nmore information at https://www.gnu.org/licenses/lgpl-3.0.html"
                ), "About");
        }

        public void formatProtocol(string protocol, int color)
        {
            if (!protocolFormat.ContainsKey(protocol))
            {
                protocolFormat.Add(protocol, color);
            }
        }
    }
}