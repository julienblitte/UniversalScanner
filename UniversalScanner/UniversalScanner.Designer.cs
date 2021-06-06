namespace UniversalScanner
{
    partial class ScannerWindow
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ScannerWindow));
            this.scanButton = new System.Windows.Forms.Button();
            this.dataGridView1 = new System.Windows.Forms.DataGridView();
            this.rightClickMenu = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.openSelectedInBrowserToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItem1 = new System.Windows.Forms.ToolStripSeparator();
            this.clearListToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exportListToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItem2 = new System.Windows.Forms.ToolStripSeparator();
            this.refreshToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.settingsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.enableIPv6ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exhaustiveprotocolsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.showUnconfiguredDevicesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutButton = new System.Windows.Forms.Button();
            this.broadcastTip = new System.Windows.Forms.ToolTip(this.components);
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).BeginInit();
            this.rightClickMenu.SuspendLayout();
            this.SuspendLayout();
            // 
            // scanButton
            // 
            this.scanButton.Location = new System.Drawing.Point(12, 12);
            this.scanButton.Name = "scanButton";
            this.scanButton.Size = new System.Drawing.Size(75, 23);
            this.scanButton.TabIndex = 0;
            this.scanButton.Text = "&Scan";
            this.scanButton.UseVisualStyleBackColor = true;
            this.scanButton.Click += new System.EventHandler(this.scanButton_Click);
            // 
            // dataGridView1
            // 
            this.dataGridView1.AllowUserToAddRows = false;
            this.dataGridView1.AllowUserToDeleteRows = false;
            this.dataGridView1.AllowUserToResizeRows = false;
            this.dataGridView1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.dataGridView1.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.dataGridView1.BackgroundColor = System.Drawing.SystemColors.Window;
            this.dataGridView1.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView1.ContextMenuStrip = this.rightClickMenu;
            this.dataGridView1.GridColor = System.Drawing.SystemColors.Window;
            this.dataGridView1.Location = new System.Drawing.Point(13, 41);
            this.dataGridView1.Name = "dataGridView1";
            this.dataGridView1.ReadOnly = true;
            this.dataGridView1.RowHeadersVisible = false;
            this.dataGridView1.RowHeadersWidth = 51;
            this.dataGridView1.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.dataGridView1.Size = new System.Drawing.Size(415, 157);
            this.dataGridView1.TabIndex = 30;
            this.dataGridView1.CellContentDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.dataGridView1_CellContentDoubleClick);
            this.dataGridView1.ColumnHeaderMouseClick += new System.Windows.Forms.DataGridViewCellMouseEventHandler(this.dataGridView1_ColumnHeaderMouseClick);
            this.dataGridView1.RowPrePaint += new System.Windows.Forms.DataGridViewRowPrePaintEventHandler(this.dataGridView1_RowPrePaint);
            // 
            // rightClickMenu
            // 
            this.rightClickMenu.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.rightClickMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.openSelectedInBrowserToolStripMenuItem,
            this.toolStripMenuItem1,
            this.refreshToolStripMenuItem,
            this.clearListToolStripMenuItem,
            this.exportListToolStripMenuItem,
            this.toolStripMenuItem2,
            this.settingsToolStripMenuItem});
            this.rightClickMenu.Name = "rightClickMenu";
            this.rightClickMenu.Size = new System.Drawing.Size(250, 126);
            // 
            // openSelectedInBrowserToolStripMenuItem
            // 
            this.openSelectedInBrowserToolStripMenuItem.Name = "openSelectedInBrowserToolStripMenuItem";
            this.openSelectedInBrowserToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.G)));
            this.openSelectedInBrowserToolStripMenuItem.Size = new System.Drawing.Size(249, 22);
            this.openSelectedInBrowserToolStripMenuItem.Text = "&Open selected in browser";
            this.openSelectedInBrowserToolStripMenuItem.Click += new System.EventHandler(this.openSelectedInBrowserToolStripMenuItem_Click);
            // 
            // toolStripMenuItem1
            // 
            this.toolStripMenuItem1.Name = "toolStripMenuItem1";
            this.toolStripMenuItem1.Size = new System.Drawing.Size(246, 6);
            // 
            // clearListToolStripMenuItem
            // 
            this.clearListToolStripMenuItem.Name = "clearListToolStripMenuItem";
            this.clearListToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.F5)));
            this.clearListToolStripMenuItem.Size = new System.Drawing.Size(249, 22);
            this.clearListToolStripMenuItem.Text = "Clear and rescan";
            this.clearListToolStripMenuItem.Click += new System.EventHandler(this.clearListToolStripMenuItem_Click);
            // 
            // exportListToolStripMenuItem
            // 
            this.exportListToolStripMenuItem.Name = "exportListToolStripMenuItem";
            this.exportListToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.S)));
            this.exportListToolStripMenuItem.Size = new System.Drawing.Size(249, 22);
            this.exportListToolStripMenuItem.Text = "&Export list";
            this.exportListToolStripMenuItem.Click += new System.EventHandler(this.exportListToolStripMenuItem_Click);
            // 
            // toolStripMenuItem2
            // 
            this.toolStripMenuItem2.Name = "toolStripMenuItem2";
            this.toolStripMenuItem2.Size = new System.Drawing.Size(246, 6);
            // 
            // refreshToolStripMenuItem
            // 
            this.refreshToolStripMenuItem.Name = "refreshToolStripMenuItem";
            this.refreshToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F5;
            this.refreshToolStripMenuItem.Size = new System.Drawing.Size(249, 22);
            this.refreshToolStripMenuItem.Text = "&Rescan";
            this.refreshToolStripMenuItem.Click += new System.EventHandler(this.refreshToolStripMenuItem_Click);
            // 
            // settingsToolStripMenuItem
            // 
            this.settingsToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.enableIPv6ToolStripMenuItem,
            this.exhaustiveprotocolsToolStripMenuItem,
            this.showUnconfiguredDevicesToolStripMenuItem});
            this.settingsToolStripMenuItem.Name = "settingsToolStripMenuItem";
            this.settingsToolStripMenuItem.Size = new System.Drawing.Size(249, 22);
            this.settingsToolStripMenuItem.Text = "&Settings";
            // 
            // enableIPv6ToolStripMenuItem
            // 
            this.enableIPv6ToolStripMenuItem.Name = "enableIPv6ToolStripMenuItem";
            this.enableIPv6ToolStripMenuItem.Size = new System.Drawing.Size(220, 22);
            this.enableIPv6ToolStripMenuItem.Text = "Enable IPv&6";
            this.enableIPv6ToolStripMenuItem.Click += new System.EventHandler(this.enableIPv6ToolStripMenuItem_Click);
            // 
            // exhaustiveprotocolsToolStripMenuItem
            // 
            this.exhaustiveprotocolsToolStripMenuItem.Name = "exhaustiveprotocolsToolStripMenuItem";
            this.exhaustiveprotocolsToolStripMenuItem.Size = new System.Drawing.Size(220, 22);
            this.exhaustiveprotocolsToolStripMenuItem.Text = "Exhaustive &protocols";
            this.exhaustiveprotocolsToolStripMenuItem.Click += new System.EventHandler(this.exhaustiveprotocolsToolStripMenuItem_Click);
            // 
            // showUnconfiguredDevicesToolStripMenuItem
            // 
            this.showUnconfiguredDevicesToolStripMenuItem.Name = "showUnconfiguredDevicesToolStripMenuItem";
            this.showUnconfiguredDevicesToolStripMenuItem.Size = new System.Drawing.Size(220, 22);
            this.showUnconfiguredDevicesToolStripMenuItem.Text = "Show &unconfigured devices";
            this.showUnconfiguredDevicesToolStripMenuItem.Click += new System.EventHandler(this.showUnconfiguredDevicesToolStripMenuItem_Click);
            // 
            // aboutButton
            // 
            this.aboutButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.aboutButton.Location = new System.Drawing.Point(353, 12);
            this.aboutButton.Name = "aboutButton";
            this.aboutButton.Size = new System.Drawing.Size(75, 23);
            this.aboutButton.TabIndex = 20;
            this.aboutButton.Text = "&About";
            this.aboutButton.UseVisualStyleBackColor = true;
            this.aboutButton.Click += new System.EventHandler(this.aboutButton_Click);
            // 
            // broadcastTip
            // 
            this.broadcastTip.ToolTipIcon = System.Windows.Forms.ToolTipIcon.Info;
            // 
            // ScannerWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(440, 210);
            this.Controls.Add(this.aboutButton);
            this.Controls.Add(this.dataGridView1);
            this.Controls.Add(this.scanButton);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.KeyPreview = true;
            this.Name = "ScannerWindow";
            this.Text = "Universal Scanner";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.ScannerWindow_FormClosed);
            this.Load += new System.EventHandler(this.ScannerWindow_Load);
            this.Shown += new System.EventHandler(this.ScannerWindow_Shown);
            this.KeyDown += new System.Windows.Forms.KeyEventHandler(this.ScannerWindow_KeyDown);
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).EndInit();
            this.rightClickMenu.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button scanButton;
        private System.Windows.Forms.DataGridView dataGridView1;
        private System.Windows.Forms.Button aboutButton;
        private System.Windows.Forms.ContextMenuStrip rightClickMenu;
        private System.Windows.Forms.ToolStripMenuItem exportListToolStripMenuItem;
        private System.Windows.Forms.ToolTip broadcastTip;
        private System.Windows.Forms.ToolStripMenuItem openSelectedInBrowserToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem clearListToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripMenuItem1;
        private System.Windows.Forms.ToolStripSeparator toolStripMenuItem2;
        private System.Windows.Forms.ToolStripMenuItem settingsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem enableIPv6ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem exhaustiveprotocolsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem showUnconfiguredDevicesToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem refreshToolStripMenuItem;
    }
}

