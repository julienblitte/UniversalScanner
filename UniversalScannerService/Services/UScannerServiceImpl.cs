using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using UniversalScannerLib;
using UScanner;

namespace UniversalScannerService
{
    public class UScannerServiceImpl : UScannerService.UScannerServiceBase, UniversalScannerLib.ScannerViewer
    {
        public event scan scanEvent;

        public System.Threading.CancellationToken ScanCancellationToken { get; set; } = new System.Threading.CancellationToken();

        private readonly ILogger<UScannerServiceImpl> _logger;
        public UScannerServiceImpl(ILogger<UScannerServiceImpl> logger)
        {
            Console.WriteLine("Create UScannerServiceImpl");
            
            RegisterScanning(this);
            new Task(() => {
                while (true)
                {
                    if (ScanCancellationToken.IsCancellationRequested) break;
                    
                    scanEvent.Invoke();
                    Console.WriteLine("Rescan started...");

                    System.Threading.Thread.Sleep(1000 * 10 * 1); // Sleep 1 minute
                }
            }, ScanCancellationToken).Start();

            _logger = logger;
        }

        public static DeviceList FoundDeviceList { get; private set; } = new DeviceList() { List = { } };

        public void deviceFound(string protocol, int version, IPAddress deviceIP, string deviceType, string serial)
        {
            var newDevice = new DeviceModel()
            {
                Protocol = protocol,
                Version = version,
                DeviceIP = deviceIP.ToString(),
                DeviceType = deviceType,
                Serial = serial
            };

            bool isFound = false;
            foreach (var d in FoundDeviceList.List)
                if (d.Equals(newDevice))
                    isFound = true;

            if (!isFound)
                FoundDeviceList.List.Add(newDevice);
        }

        public void formatProtocol(string protocol, int color)
        {
        }

        public override Task<DeviceList> GetFoundDevcies(DeviceFilter request, ServerCallContext context)
        {
            return Task.FromResult(FoundDeviceList);
        }

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
    }
}
