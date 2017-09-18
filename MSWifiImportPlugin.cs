/*
  Based on: KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2017 Dominik Reichl <dominik.reichl@t-online.de>
  
  MSWifiImport - Plugin for importing Windows Wifi information.
  Copyright (C) 2017 Christopher R. Nerz <keepass@phoenixes.de>
  https://elgesl.github.io/keepass-mswifiimport/

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

  The current version of the source code of the plugin can be found at
  https://github.com/elgesl/keepass-mswifiimport
*/

using System;
using System.Xml.Serialization;
using System.IO;
using System.Windows.Forms;

using KeePassLib;
using KeePass.Plugins;
using System.Drawing;

namespace MSWifiImportPlugin
{
    /// <summary>
    /// That is the just the interface to the plugin system of KeePass 2.
    /// </summary>
    /// <remarks>
    /// One of our problems is that we cannot export to single files nor can we export
    /// every entry, but only quite special ones. Therefore, we can (so far) not use the
    /// export system of KeePass, but have to improvise:
    /// We add two entries to the menu of entries if those entries are supported and
    /// remove them afterwards again.
    /// </remarks>
    public sealed class MSWifiImportPluginExt : Plugin
    {
        /// <summary>To be honest, this is copy and past from the examples...</summary>
        private IPluginHost phHost = null;
        /// <summary>To be honest, this is copy and past from the examples...</summary>
        private const String nameOfSelectedEntires = "m_ctxEntryMassModify";

        /// <summary>The Menu "selected items" (in the menu you get by right clicking on an entry)</summary>
        /// <remark>
        /// Hopefully a temporary way to solve the problem explained in <see cref="MSWifiImportPluginExt"/>
        /// </remark>
        private ToolStripMenuItem selectedItemsMenu;

        /// <summary>The seperator seperating our stuff from the standard menu items</summary>
        /// <remark>
        /// Hopefully a temporary way to solve the problem explained in <see cref="MSWifiImportPluginExt"/>
        /// </remark>
        private int addToWindowsSep;

        /// <summary>The entry to export the entries to Windows</summary>
        /// <remark>
        /// Hopefully a temporary way to solve the problem explained in <see cref="MSWifiImportPluginExt"/>
        /// </remark>
        private ToolStripItem addToWindows;

        /// <summary>The entry to export the entries to .xml files</summary>
        /// <remark>
        /// Hopefully a temporary way to solve the problem explained in <see cref="MSWifiImportPluginExt"/>
        /// </remark>
        private ToolStripItem exportToXML;

        /// <summary>Our icon designed by Freepik from Flaticon</summary>
        public override Image SmallIcon { get { return Properties.Resources.B64x64_Imp_Wifi.ToBitmap(); } }

        /// <summary>Here, I publish the version information.</summary>
        /// <remark>
        /// The current version of the plugin sourcecode can always be found at
        /// https://elgesl.github.io/keepass-mswifiimport/
        /// </remark>
        public override string UpdateUrl
        { get { return "https://raw.githubusercontent.com/elgesl/keepass-mswifiimport/master/VersionsInfo.txt"; } }

        public override bool Initialize(IPluginHost host)
        {
            phHost = host;
            // We include the new format to the pool
            phHost.FileFormatPool.Add(new MSWifiXML());
            phHost.FileFormatPool.Add(new MSWifiSystem());

            /* Actually, I want the above "FileFormats" to be able to export, too. However only *some*
             * quite special entries can be exportet. Thus, we cannot export via File -> Export (or
             * rightclick and then Selected items -> export) as we can thereby neither test if the
             * entries are correct ones nor can we export to several files (as it would be necessary
             * for the export to .xml-files).
             * As (hopefully temporary) solution for this problem, we add corresponding entries to the
             * submenu "selected items", but only if only entries with Wlan-entries are selected */
            ToolStripItem[] searchSelectedItems
                = phHost.MainWindow.EntryContextMenu.Items.Find(nameOfSelectedEntires, false);

            selectedItemsMenu = null;
            foreach (ToolStripItem item in searchSelectedItems)
            {
                if (item.GetType() == typeof(ToolStripMenuItem))
                {
                    if (selectedItemsMenu != null)
                        return false;
                    else
                        selectedItemsMenu = (ToolStripMenuItem)item;
                }
            }

            if (selectedItemsMenu == null)
                return false;

            selectedItemsMenu.DropDownOpened += this.AddExportToMenu;
            selectedItemsMenu.DropDownClosed += this.RemoveExportToMenu;
            return true;
        }

        /// <summary>
        /// When we open the menu of entires, then we allow to export to Windows or .xml files
        /// if only supported entries are chosen.
        /// </summary>
        /// <param name="sender">Ignored</param>
        /// <param name="e">Ignored</param>
        /// <remark>
        /// Hopefully a temporary way to solve the problem explained in <see cref="MSWifiImportPluginExt"/>
        /// </remark>
        public void AddExportToMenu(object sender, EventArgs e)
        {
            if (phHost.MainWindow.GetSelectedEntries() == null ||
                    phHost.MainWindow.GetSelectedEntries().Length == 0)
                return;

            WlanProfile profile = new WlanProfile();
            // Check whether the entries are supported
            foreach (PwEntry entry in phHost.MainWindow.GetSelectedEntries())
            {
                if (!entry.Strings.Exists(FieldNames.SSIDHex))
                    return;

                profile.LoadFrom(phHost.Database, entry);

                if (!profile.IsValid)
                    return;
            }

            // All entries are supported, so add our stuff
            addToWindowsSep = selectedItemsMenu.DropDown.Items.Add(new ToolStripSeparator());
            addToWindows = selectedItemsMenu.DropDown.Items.Add("In Windows einfügen", null, AddEntriesToWindows);
            exportToXML = selectedItemsMenu.DropDown.Items.Add("In .xml Datei exportieren", null, AddEntriesToXML);
        }

        /// <summary>
        /// When we close the menu of entires, then we have to remove our stuff again.
        /// </summary>
        /// <param name="sender">Ignored</param>
        /// <param name="e">Ignored</param>
        /// <remark>
        /// Hopefully a temporary way to solve the problem explained in <see cref="MSWifiImportPluginExt"/>
        /// </remark>
        public void RemoveExportToMenu(object sender, EventArgs e)
        {
            selectedItemsMenu.DropDownItems.Remove(exportToXML);
            selectedItemsMenu.DropDownItems.Remove(addToWindows);
            selectedItemsMenu.DropDown.Items.RemoveAt(addToWindowsSep);
        }

        /// <summary>Add all entries, we selected to the Windows system.</summary>
        /// <param name="sender">Ignored</param>
        /// <param name="e">Ignored</param>
        public void AddEntriesToWindows(object sender, EventArgs e)
        {
            XmlSerializer xml = new XmlSerializer(typeof(WlanProfile));
            WlanProfile profile = new WlanProfile();
            String xmlVersionOfProfile = null;
            StringWriter writer = null;

            WinWlan.SystemInterface system = new WinWlan.SystemInterface();
            WinWlan.WlanInterface[] interfaces = system.Interfaces;
            if (interfaces.Length == 0)
                return;
            WinWlan.WlanInterface curInterface = interfaces[0];

            foreach (PwEntry entry in phHost.MainWindow.GetSelectedEntries())
            {
                profile.LoadFrom(phHost.Database, entry);

                if (!profile.IsValid)
                    continue;

                writer = new StringWriter();
                xml.Serialize(writer, profile);
                xmlVersionOfProfile = writer.ToString();
                curInterface.SetProfile(WinWlan.WlanProfileFlags.AllUser, xmlVersionOfProfile, true);
            }
        }

        /// <summary>Add all entries, we selected to the Windows system.</summary>
        /// <param name="sender">Ignored</param>
        /// <param name="e">Ignored</param>
        public void AddEntriesToXML(object sender, EventArgs e)
        {
            XmlSerializer xml = new XmlSerializer(typeof(WlanProfile));
            WlanProfile profile = new WlanProfile();
            StreamWriter stream;

            // If we only export one entry, then we let the user choose the .xml file otherwise
            // only the folder.
            if (phHost.MainWindow.GetSelectedEntries().Length == 1)
            {
                profile.LoadFrom(phHost.Database, phHost.MainWindow.GetSelectedEntry(true));
                SaveFileDialog fileDialog = new SaveFileDialog();
                fileDialog.Filter = "XML files (*.xml)|*.xml";

                if (fileDialog.ShowDialog() != DialogResult.OK)
                    return;
                if ((stream = new StreamWriter(fileDialog.OpenFile())) == null)
                    return;
                xml.Serialize(stream, profile);
                stream.Close();
            }
            else
            {
                FolderBrowserDialog folderBrowser = new FolderBrowserDialog();
                folderBrowser.ShowNewFolderButton = true;
                folderBrowser.Description = "Verzeichnis für die .xml Dateien wählen";
                if (folderBrowser.ShowDialog() != DialogResult.OK)
                    return;

                String path;

                foreach (PwEntry entry in phHost.MainWindow.GetSelectedEntries())
                {
                    profile.LoadFrom(phHost.Database, entry);

                    if (!profile.IsValid)
                        continue;

                    path = String.Format("{0}\\{1}.xml", folderBrowser.SelectedPath, profile.NameOrSSID);
                    if (File.Exists(path))
                    {
                        KeePass.UI.VistaTaskDialog vtd = new KeePass.UI.VistaTaskDialog();
                        vtd.CommandLinks = false;
                        vtd.MainInstruction = String.Format("Es ist bereits eine Datei namens {0} vorhanden.\n" +
                            "Soll die Datei ersetzt werden, ein neuer Dateiname erzeugt werden oder der" +
                            "Eintrag übersprungen werden?", path);
                        vtd.SetIcon(KeePass.UI.VtdCustomIcon.Question);
                        vtd.WindowTitle = String.Format("Zieldatei für {0}", profile.NameOrSSID);

                        vtd.AddButton((int)MSWifi.BehaviourForExEntry.REPLACE, "Ersetzen", null);
                        vtd.AddButton((int)MSWifi.BehaviourForExEntry.RENAME_NEW_ONE, "Neuer Dateiname", null);
                        vtd.AddButton((int)MSWifi.BehaviourForExEntry.CANCEL_WITHOUT_ERROR, "Überspringen", null);
                        vtd.ShowDialog();
                        switch (vtd.Result)
                        {
                            case (int)MSWifi.BehaviourForExEntry.REPLACE:
                                File.Delete(path);
                                break;
                            case (int)MSWifi.BehaviourForExEntry.RENAME_NEW_ONE:
                                for (int no = 2; File.Exists(path); ++no)
                                {
                                    path = String.Format("{0}\\{1} ({2}).xml", folderBrowser.SelectedPath,
                                                         profile.NameOrSSID, no);
                                }
                                break;
                            default:
                            case (int)MSWifi.BehaviourForExEntry.CANCEL_WITHOUT_ERROR:
                                continue;
                        }
                    }

                    stream = new StreamWriter(path, false);
                    xml.Serialize(stream, profile);
                    stream.Close();
                }
            }
        }
    }
}
