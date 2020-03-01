using System;
using System.Collections;
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

        private DataTable found_devices;
        private BindingSource binding;
        private Dictionary<string, int> protocolFormat;

        public ScannerWindow()
        {
            InitializeComponent();

            found_devices = new DataTable();
            found_devices.Columns.Add(new DataColumn("Protocol", typeof(string)));
            found_devices.Columns.Add(new DataColumn("IP address", typeof(string)));
            found_devices.Columns.Add(new DataColumn("Type", typeof(string)));
            found_devices.Columns.Add(new DataColumn("Unique ID", typeof(string)));

            binding = new BindingSource();
            binding.DataSource = found_devices;

            dataGridView1.DataSource = binding;

            dataGridView1.Columns[1].SortMode = DataGridViewColumnSortMode.Programmatic;

            protocolFormat = new Dictionary<string, int>();
        }

        private void scanButton_Click(object sender, EventArgs e)
        {
            scanEvent.Invoke();
        }

        public void deviceFound(string protocol, string deviceIP, string deviceType, string serial)
        {
            if (IsDisposed)
                return;

            if (InvokeRequired)
            {
                Invoke(new MethodInvoker(() => addDevice(protocol, deviceIP, deviceType, serial)));
            }
            else
            {
                addDevice(protocol, deviceIP, deviceType, serial);
            }
        }

        private void addDevice(string protocol, string deviceIP, string deviceType, string serial)
        {
            if (!found_devices.Select().ToList().Exists(col => (col[0].ToString() == protocol &&
                col[1].ToString() == deviceIP)))
            {
                found_devices.Rows.Add(protocol, deviceIP, deviceType, serial);
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
                String.Format("{0} {1}.{2}\nBuild date {3:0000}-{4:00}-{5:00}\n\nCopyright {6}\n\n{7}",
                    versionInfo.ProductName, versionInfo.FileMajorPart, versionInfo.FileMinorPart,
                    versionInfo.ProductBuildPart, (versionInfo.ProductPrivatePart / 100), (versionInfo.ProductPrivatePart % 100),
                    versionInfo.LegalCopyright,
                    "Program under GNU Lesser General Public License 3.0,\nmore information at https://www.gnu.org/licenses/lgpl-3.0.html"
                ), "About");
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
            
            int order;

            column = dataGridView1.Columns[e.ColumnIndex];

            if (column.SortMode == DataGridViewColumnSortMode.Programmatic)
            {
                order = (column.HeaderCell.SortGlyphDirection == SortOrder.Ascending ? -1 : 1);

                /*
                DataTable new_devices;

                new_devices = new DataTable();
                for (int c = 0; c < found_devices.Columns.Count; c++)
                {
                    new_devices.Columns.Add(found_devices.Columns[c]);
                }
                new_devices.Columns.Add("order");
                for (int c = 0; c < found_devices.Rows.Count; c++)
                {
                    new_devices.Rows.Add(found_devices.Rows[c]);
                }
                found_devices = new_devices;
                */

                //binding.DataSource = binding.OrderBy(p => p, new IPComparer()).

                binding.Sort = string.Format("{0} {1}", column.DataPropertyName, (order > 0 ? "ASC" : "DESC"));

                column.HeaderCell.SortGlyphDirection = (order > 0 ? SortOrder.Ascending : SortOrder.Descending);
            }
        }
    }

    class IPComparer : IComparer<string>
    {
        public int Compare(string a, string b)
        {
            return Enumerable.Zip(a.Split('.'), b.Split('.'),
                                 (x, y) => int.Parse(x).CompareTo(int.Parse(y)))
                             .FirstOrDefault(i => i != 0);
        }
    }
}
