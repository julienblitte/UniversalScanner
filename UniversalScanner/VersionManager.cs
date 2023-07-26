using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UniversalScanner
{
    public delegate void OnFoundUpdates();

    public class VersionManager
    {
        private readonly string UpdateUrl = "https://api.github.com/repos/julienblitte/UniversalScanner/releases/latest";

        private DateTime localBuildDate;
        private FileVersionInfo localVersion;

        public OnFoundUpdates onUpdateAvailable;

        public FileVersionInfo getVersionInfo()
        {
            return localVersion;
        }

        public DateTime getBuildDate()
        {
            return localBuildDate;
        }

        public VersionManager()
        {
            localVersion = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location);
            localBuildDate = new DateTime(2000, 1, 1).AddDays(localVersion.FileBuildPart).AddSeconds(localVersion.FilePrivatePart * 2);
        }

        public static void checkForUpdateThread(Object obj)
        {
            VersionManager sender;
            string json;
            Regex tag;

            sender = (VersionManager)obj;
            try
            {
                WebClient updater;
                Stream s;

                updater = new WebClient();
                updater.Headers.Add("user-agent", String.Format("Mozilla/4.0 (compatible; {0})", sender.localVersion.ProductName));

                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                s = updater.OpenRead(sender.UpdateUrl);
                StreamReader reader = new StreamReader(s);
                json = reader.ReadToEnd();
                s.Close();
                reader.Close();
            }
            catch (Exception)
            {
                return;
            }

            tag = new Regex("\"tag_name\" *: *\"([0-9]{4}-[0-9]{2}-[0-9]{2})\"");
            Match m = tag.Match(json);
            if (m.Success)
            {
                string onlineVersion = m.Groups[1].Value;
                string[] onlineVersionComps;
                TimeSpan timeDiff;

                onlineVersionComps = onlineVersion.Split('-');
                DateTime onlineVersionDate = new DateTime(Int32.Parse(onlineVersionComps[0]), Int32.Parse(onlineVersionComps[1]), Int32.Parse(onlineVersionComps[2]));
                DateTime localVersionDate = sender.localBuildDate;

                timeDiff = onlineVersionDate - localVersionDate;

                if (timeDiff.Days > 1)
                {
                    sender.onUpdateAvailable();
                }
            }
        }

        public void checkForUpdate()
        {
            Thread t;
            
            t = new Thread(checkForUpdateThread);
            t.Start(this);
        }
    }
}
