﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace UniversalScanner
{
    public partial class ScannerWindow : Form, ScannerViewer
    {
        public event scan scanEvent;

        private DataTable foundDeviceList;
        private BindingSource binding;
        private Dictionary<string, int> protocolFormat;

        private VersionManager localVersion;

        enum Columns
        { 
            Protocol = 0,
            Version = 1,
            IPAddress = 2,
            Type = 3,
            UniqueId = 4
        };
        private readonly string[] ColumnNames =
        {
            "Protocol",
            "Version",
            "IP address",
            "Type", 
            "Unique ID"
        };

        public ScannerWindow()
        {
            InitializeComponent();

            foundDeviceList = new DataTable();
            foundDeviceList.Columns.Add(new DataColumn(ColumnNames[(int)Columns.Protocol], typeof(string)));
            foundDeviceList.Columns.Add(new DataColumn(ColumnNames[(int)Columns.Version], typeof(int)));
            foundDeviceList.Columns.Add(new DataColumn(ColumnNames[(int)Columns.IPAddress], typeof(string)));
            foundDeviceList.Columns.Add(new DataColumn(ColumnNames[(int)Columns.Type], typeof(string)));
            foundDeviceList.Columns.Add(new DataColumn(ColumnNames[(int)Columns.UniqueId], typeof(string)));

            binding = new BindingSource();
            binding.DataSource = foundDeviceList;

            dataGridView1.DataSource = binding;

            dataGridView1.Columns[(int)Columns.IPAddress].SortMode = DataGridViewColumnSortMode.Programmatic;
            dataGridView1.Columns[(int)Columns.Version].Visible = false;

            protocolFormat = new Dictionary<string, int>();

            localVersion = new VersionManager();

            if (Config.getInstance().DebugMode)
            {
                Logger.getInstance().setLevel(Logger.DebugLevel.Debug);
            }
        }

        private void scanButton_Click(object sender, EventArgs e)
        {
            scanEvent.Invoke();
        }

        public void deviceFound(string protocol, int version, IPAddress deviceIP, string deviceType, string deviceUUID)
        {
            if (IsDisposed)
                return;

            if (deviceIP.AddressFamily == AddressFamily.InterNetwork && !Config.getInstance().EnableIPv4)
                return;

            if (deviceIP.AddressFamily == AddressFamily.InterNetworkV6 && !Config.getInstance().EnableIPv6)
                return;

            if (InvokeRequired)
            {
                Invoke(new MethodInvoker(() => addDevice(protocol, version, deviceIP.ToString(), deviceType, deviceUUID)));
            }
            else
            {
                addDevice(protocol, version, deviceIP.ToString(), deviceType, deviceUUID);
            }
        }

        private void addDevice(string protocol, int version, string deviceIP, string deviceType, string deviceUUID)
        {
            DataRow[] existingRow;

            if (Config.getInstance().ForceGenericProtocols)
            {
                // find same protocol and same address
                existingRow = foundDeviceList.Select(String.Format("`{0}` = '{1}' AND `{2}` = '{3}'", ColumnNames[(int)Columns.Protocol], protocol, ColumnNames[(int)Columns.IPAddress], deviceIP));
            }
            else
            {
                // find only same address
                existingRow = foundDeviceList.Select(String.Format("`{0}` = '{1}'", ColumnNames[(int)Columns.IPAddress], deviceIP));
            }

            if (existingRow.Length == 0)
            {
                foundDeviceList.Rows.Add(protocol, version, deviceIP, deviceType, deviceUUID);
            }
            else
            {
                int existingVersion;

                // device exists but with lower version, update it
                existingVersion = existingRow[0].Field<int>((int)Columns.Version);
                if (version > existingVersion)
                {
                    // protocol and IP Address already set
                    // update only Version, Type and UniqueId
                    existingRow[0].BeginEdit();
                    existingRow[0][(int)Columns.Protocol] = protocol;
                    existingRow[0][(int)Columns.Version] = version;
                    //existingRow[0][(int)Columns.IPAddress] = deviceIP;
                    existingRow[0][(int)Columns.Type] = deviceType;
                    existingRow[0][(int)Columns.UniqueId] = deviceUUID;
                    existingRow[0].EndEdit();
                }
            }
        }

        private void ScannerWindow_FormClosed(object sender, FormClosedEventArgs e)
        {
            Logger.getInstance().Dispose(); // mandatory to save pcap data when debugging
            Application.Exit();
        }

        private void dataGridView1_CellContentDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            string ip;

            if (e.RowIndex < 0)
                return;

            ip = dataGridView1.Rows[e.RowIndex].Cells[(int)Columns.IPAddress].Value.ToString();
            //ip = foundDeviceList.Rows[e.RowIndex].ItemArray[(int)Columns.IPAddress].ToString();
            if (ip != "")
            {
                IPAddress parsed;

                if (IPAddress.TryParse(ip, out parsed))
                {
                    switch (parsed.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            Process.Start(String.Format("http://{0}", parsed.ToString()));
                            break;
                        case AddressFamily.InterNetworkV6:
                            Process.Start(String.Format("http://[{0}]", parsed.ToString()));
                            break;
                    }
                }
            }
        }

        private void aboutButton_Click(object sender, EventArgs e)
        {
            FileVersionInfo versionInfo;
            DateTime buildDate;

            versionInfo = localVersion.getVersionInfo();
            buildDate = localVersion.getBuildDate();

            MessageBox.Show(this,
                String.Format("{0} {1}.{2}\nBuild date {3}\n\nCopyright {4}\n\n{5}",
                    versionInfo.ProductName, versionInfo.FileMajorPart, versionInfo.FileMinorPart,
                    buildDate.ToString("yyyy-MM-dd HH:mm:ss"), versionInfo.LegalCopyright,
                    "Program under GNU Lesser General Public License 3.0,\nmore information at https://www.gnu.org/licenses/lgpl-3.0.html"
                ), "About");
        }

        private void ScannerWindow_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Control && e.KeyCode == Keys.A)
            {
                dataGridView1.SelectAll();
            }
        }

        private void exportAsCSV()
        {
            StringBuilder sb;

            string local_name = Thread.CurrentThread.CurrentCulture.EnglishName;
            string local_separator = Thread.CurrentThread.CurrentCulture.TextInfo.ListSeparator;

            SaveFileDialog saveAs = new SaveFileDialog();
            saveAs.Filter = "CSV file|*.csv|CSV " + local_name + " format|*.csv|TSV file|*.txt;*.tsv";
            saveAs.Title = "Export device list";
            saveAs.OverwritePrompt = true;
            saveAs.CheckPathExists = true;
            saveAs.ShowDialog();

            if (saveAs.FileName != "")
            {
                string quote_start = "\"";
                string quote_end = "\"";
                string quote_escape = quote_end + quote_end;
                string separator = ",";

                switch (saveAs.FilterIndex)
                {
                    case 1:
                        // keep the default settings
                        break;
                    case 2:
                        quote_start = "\"";
                        quote_end = "\"";
                        separator = local_separator;
                        break;
                    case 3:
                        quote_start = "";
                        quote_end = "";
                        separator = "\t";
                        break;
                }

                sb = new StringBuilder();

                var headers = dataGridView1.Columns.Cast<DataGridViewColumn>();
                sb.AppendLine(string.Join(separator, headers.Select(
                    column => quote_start + ((quote_end != "") ? column.HeaderText.Replace(quote_end, quote_escape) : column.HeaderText) + quote_end
                    ).ToArray()));

                foreach (DataGridViewRow row in dataGridView1.Rows)
                {
                    var cells = row.Cells.Cast<DataGridViewCell>();
                    sb.AppendLine(string.Join(separator, cells.Select(
                        cell => quote_start + ((quote_end != "") ? cell.Value.ToString().Replace(quote_end, quote_escape) : cell.Value.ToString()) + quote_end
                        ).ToArray()));
                }

                File.WriteAllText(saveAs.FileName, sb.ToString());
            }

        }

        public void formatProtocol(string protocol, int color)
        {
            if (!protocolFormat.ContainsKey(protocol))
            {
                protocolFormat.Add(protocol, color);
            }
        }

        private void exportListToolStripMenuItem_Click(object sender, EventArgs e)
        {
            exportAsCSV();
        }

        private void dataGridView1_RowPrePaint(object sender, DataGridViewRowPrePaintEventArgs e)
        {
            int index = e.RowIndex;
            string protocol = (string)dataGridView1.Rows[index].Cells[0].Value;
            
            if (protocolFormat.ContainsKey(protocol))
            {
                dataGridView1.Rows[index].DefaultCellStyle.ForeColor = Color.FromArgb(protocolFormat[protocol]);
            }
        }

        private void dataGridView1_ColumnHeaderMouseClick(object sender, DataGridViewCellMouseEventArgs e)
        {
            DataGridViewColumn column;


            column = dataGridView1.Columns[e.ColumnIndex];

            if (column.SortMode == DataGridViewColumnSortMode.Programmatic)
            {
                int order;
                IPAddress value;
                int count;
                UInt32[] cache;
                int[] newOrder;

                order = (column.HeaderCell.SortGlyphDirection == SortOrder.Ascending ? -1 : 1);

                count = foundDeviceList.Rows.Count;

                // caching data
                cache = new UInt32[count];
                for (int i=0; i < count; i++)
                {
                    string ip;

                    ip = foundDeviceList.Rows[i].Field<string>("IP address");

                    if (IPAddress.TryParse(ip, out value))
                    {
                        byte[] valueBytes = value.GetAddressBytes();
                        cache[i] = (UInt32)(valueBytes[0] << 24
                            | valueBytes[1] << 16
                            | valueBytes[2] << 8
                            | valueBytes[3]);
                    }
                    else
                    {
                        cache[i] = 0xffffffff;
                    }
                }

                // sorting cache O(n^2)
                // find extermum item (min or max) and move it to the end of the list
                // repeat operation, search the new extremum in the list except the moved item at the end
                newOrder = new int[count];
                for (int j=0; j < count; j++)
                {
                    UInt32 extremum;
                    int extremumIndex;

                    if (order > 0)
                    {
                        // find min value
                        extremum = 0xffffffff;
                        extremumIndex = 0;
                        for (int i = 0; i < count - j; i++)
                        {
                            if (cache[i] < extremum)
                            {
                                extremum = cache[i];
                                extremumIndex = i;
                            }
                        }
                    }
                    else
                    {
                        // find max value
                        extremum = 0;
                        extremumIndex = 0;
                        for (int i = 0; i < count - j; i++)
                        {
                            if (cache[i] > extremum)
                            {
                                extremum = cache[i];
                                extremumIndex = i;
                            }
                        }
                    }

                    // move value to the end, shift the rest
                    for (int i=extremumIndex; i < count-j-1; i++)
                    {
                        cache[i] = cache[i + 1];
                    }
                    cache[count - j - 1] = extremum;

                    newOrder[j] = extremumIndex;
                }

                // deploying new order
                for (int i=0; i < count; i++)
                {
                    DataRow line = foundDeviceList.Rows[newOrder[i]];
                    foundDeviceList.ImportRow(line);
                    foundDeviceList.Rows.RemoveAt(newOrder[i]);
                }
                // use natural display order as we sorted directly DataTable, not the DataGridView
                binding.RemoveSort();

                column.HeaderCell.SortGlyphDirection = (order > 0 ? SortOrder.Ascending : SortOrder.Descending);
            }
        }

        public void updateAvailable()
        {
            this.Invoke(new MethodInvoker(delegate
            {
                newVersion.Visible = true;
            }));
        }

        private void ScannerWindow_Load(object sender, EventArgs e)
        {
#if DEBUG
            if (!Config.getInstance().DebugMode)
            {
                if (MessageBox.Show(String.Format("This version is a debug version, it can be unstable and with lower performances.\n\n"
                    + "You might want to download the release version at:\n{0}\n\n"
                    + "Do you really want to continue?",
                    "https://github.com/julienblitte/UniversalScanner/releases"), "Debug version", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2)
                    != DialogResult.Yes)
                {
                    Application.Exit();
                }
            }
            this.Text += " - Debug version " + localVersion.getVersionInfo().ProductVersion;
            newVersion.Visible = true;
            newVersion.Text = "Update to official release";
#else
            localVersion.onUpdateAvailable += updateAvailable;
            localVersion.checkForUpdate();
#endif
        }

        private void openSelectedInBrowserToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var selRows = dataGridView1.SelectedRows;
            
            if (selRows.Count == 1)
            {
                dataGridView1_CellContentDoubleClick(dataGridView1, new DataGridViewCellEventArgs((int)Columns.IPAddress, selRows[0].Index));
            }
        }

        private void clearListToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(this, "The current list will be cleared. Are you sure?", "Clear the discovered item list",
                MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes)
            {
                foundDeviceList.Clear();
                dataGridView1.Refresh();

                scanEvent.Invoke();
            }
        }

        private void enableIPv6ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Config.getInstance().EnableIPv6 = !Config.getInstance().EnableIPv6;
            enableIPv6ToolStripMenuItem.Checked = Config.getInstance().EnableIPv6;
        }

        private void exhaustiveprotocolsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Config.getInstance().ForceGenericProtocols = !Config.getInstance().ForceGenericProtocols;
            exhaustiveprotocolsToolStripMenuItem.Checked = Config.getInstance().ForceGenericProtocols;
        }

        private void showUnconfiguredDevicesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            bool status;

            status = Config.getInstance().ForceZeroConf || Config.getInstance().ForceLinkLocal;
            status = !status;

            Config.getInstance().ForceZeroConf = status;
            Config.getInstance().ForceLinkLocal = status;
            showUnconfiguredDevicesToolStripMenuItem.Checked = status;
        }

        private void refreshToolStripMenuItem_Click(object sender, EventArgs e)
        {
            scanEvent.Invoke();
        }

        private void ScannerWindow_Shown(object sender, EventArgs e)
        {
            enableIPv6ToolStripMenuItem.Checked = Config.getInstance().EnableIPv6;
            exhaustiveprotocolsToolStripMenuItem.Checked = Config.getInstance().ForceGenericProtocols;
            showUnconfiguredDevicesToolStripMenuItem.Checked = Config.getInstance().ForceZeroConf || Config.getInstance().ForceLinkLocal;
        }

        private void newVersion_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            Process.Start("https://github.com/julienblitte/UniversalScanner/releases/latest");
        }
    }
}
