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
using System.Text.RegularExpressions;
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

            // TODO: add protocol version column
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

        // TODO: change, add protocol version
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

        // TODO: change, add protocol version
        private void addDevice(string protocol, string deviceIP, string deviceType, string serial)
        {
            // TODO: if already exists, replace line with highest protocol version
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


            column = dataGridView1.Columns[e.ColumnIndex];

            if (column.SortMode == DataGridViewColumnSortMode.Programmatic)
            {
                int order;
                Regex ipFormat;
                int count;
                UInt32[] cache;
                int[] newOrder;

                ipFormat = new Regex("^([0-9 ]+)\\.([0-9 ]+)\\.([0-9 ]+)\\.([0-9 ]+)$", RegexOptions.Compiled);
                order = (column.HeaderCell.SortGlyphDirection == SortOrder.Ascending ? -1 : 1);

                count = found_devices.Rows.Count;

                // caching data
                cache = new UInt32[count];
                for (int i=0; i < count; i++)
                {
                    string ip;
                    Match m;

                    ip = found_devices.Rows[i].Field<string>("IP address");
                    m = ipFormat.Match(ip);

                    if (m.Success)
                    {
                        cache[i] = UInt32.Parse(m.Groups[1].Value) << 24
                            | UInt32.Parse(m.Groups[2].Value) << 16
                            | UInt32.Parse(m.Groups[3].Value) << 8
                            | UInt32.Parse(m.Groups[4].Value);
                    }
                    else
                    {
                        cache[i] = 0;
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
                    DataRow line = found_devices.Rows[newOrder[i]];
                    found_devices.ImportRow(line);
                    found_devices.Rows.RemoveAt(newOrder[i]);
                }
				// use natural display order as we sorted directly DataTable, not the DataGridView
                binding.RemoveSort();

                column.HeaderCell.SortGlyphDirection = (order > 0 ? SortOrder.Ascending : SortOrder.Descending);
            }
        }

    }
}
