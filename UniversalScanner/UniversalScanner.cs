using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace UniversalScanner
{

    public partial class ScannerWindow : Form, ScannerViewer
    {
        public event scan scanEvent;

        DataTable found_devices;

        public ScannerWindow()
        {
            InitializeComponent();

            found_devices = new DataTable();
            found_devices.Columns.Add(new DataColumn("Protocol", typeof(string)));
            found_devices.Columns.Add(new DataColumn("IP address", typeof(string)));
            found_devices.Columns.Add(new DataColumn("Type", typeof(string)));
            found_devices.Columns.Add(new DataColumn("Unique ID", typeof(string)));
            dataGridView1.DataSource = found_devices;
        }

        private void scanButton_Click(object sender, EventArgs e)
        {
            scanEvent.Invoke();
        }

        public void deviceFound(string protocol, string deviceIP, string deviceType, string serial, int color)
        {
			if (IsDisposed)
                return;

            if (InvokeRequired)
            {
                Invoke(new MethodInvoker(() => addDevice(protocol, deviceIP, deviceType, serial, color)));
            }
            else
            {
                addDevice(protocol, deviceIP, deviceType, serial, color);
            }
        }

        private void addDevice(string protocol, string deviceIP, string deviceType, string serial, int color = 0)
        {
            if (!found_devices.Select().ToList().Exists(col => (col[0].ToString() == protocol &&
                col[1].ToString() == deviceIP)))
            {
                found_devices.Rows.Add(protocol, deviceIP, deviceType, serial);
                if (color != 0)
                {
                    dataGridView1.Rows[found_devices.Rows.Count-1].DefaultCellStyle.ForeColor = Color.FromArgb(color);
                }
            }
        }

        private void ScannerWindow_FormClosed(object sender, FormClosedEventArgs e)
        {
            Application.Exit();
        }

        private void dataGridView1_CellContentDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            string ip;

            if (e.RowIndex < 0)
                return;

            ip = found_devices.Rows[e.RowIndex].ItemArray[1].ToString();
            if (ip != "")
            {
                System.Diagnostics.Process.Start("http://" + ip);
            }
        }

        private void aboutButton_Click(object sender, EventArgs e)
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location);

            MessageBox.Show(this,
                String.Format("{0} {1}.{2}\n\nBuild date {3:0000}-{4:00}-{5:00}",
                    versionInfo.ProductName, versionInfo.FileMajorPart, versionInfo.FileMinorPart,
                    versionInfo.ProductBuildPart, (versionInfo.ProductPrivatePart / 100), (versionInfo.ProductPrivatePart % 100)), "About");
        }

        private void ScannerWindow_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Control && e.KeyCode == Keys.S)
            {
                exportAsCSV();
            }
            else if (e.Control && e.KeyCode == Keys.A)
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
            saveAs.Filter = "CSV file|*.csv|CSV "+ local_name + " format|*.csv|TSV file|*.txt;*.tsv";
            saveAs.Title = "Export device list";
            saveAs.OverwritePrompt = true;
            saveAs.CheckPathExists = true;
            saveAs.ShowDialog();

            if (saveAs.FileName != "")
            {
                string quote_start = "\"";
                string quote_end = "\"";
                string quote_escape = quote_end+quote_end;
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
                    column => quote_start + ((quote_end != "")? column.HeaderText.Replace(quote_end, quote_escape):column.HeaderText) + quote_end
                    ).ToArray()));

                foreach (DataGridViewRow row in dataGridView1.Rows)
                {
                    var cells = row.Cells.Cast<DataGridViewCell>();
                    sb.AppendLine(string.Join(separator, cells.Select(
                        cell => quote_start + ((quote_end != "")?cell.Value.ToString().Replace(quote_end, quote_escape):cell.Value.ToString()) + quote_end
                        ).ToArray()));
                }

                File.WriteAllText(saveAs.FileName, sb.ToString());
            }

        }

        private void exportListToolStripMenuItem_Click(object sender, EventArgs e)
        {
            exportAsCSV();
        }

    }
}
