/*
  Based on: KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2017 Dominik Reichl <dominik.reichl@t-online.de>
  
  MSWifiImport - Plugin for importing Windows Wifi information.
  Copyright (C) 2017 Christopher R. Nerz <keepass@phoenixes.de>
  https://chris.nerz.me/en/keepass-mswifiimportplugin/

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
    public sealed class MSWifiImportPluginExt : Plugin
    {
        private IPluginHost phHost = null;
        private const String nameOfSelectedEntires = "m_ctxEntryMassModify";
        private ToolStripMenuItem selectedItemsMenu;
        private int addToWindowsSep;
        private ToolStripItem addToWindows;

        public override Image SmallIcon { get { return Properties.Resources.B64x64_Imp_Wifi.ToBitmap(); } }

        public override string UpdateUrl
        { get { return "https://usvn.brandybock.de/chris/Programmieren/KeePass_WifiPlugin/LastVersion/VersionsInfo.txt"; } }

        public override bool Initialize(IPluginHost host)
        {
            phHost = host;
            // We include the new format to the pool
            phHost.FileFormatPool.Add(new MSWifiXML());
            phHost.FileFormatPool.Add(new MSWifiSystem());

            // We will add to the submenu "ausgewählte Elemente" ("selected items"), but only if only
            // Entries with Wlan-entries are selected
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

        public void AddExportToMenu(object sender, EventArgs e)
        {
            if (phHost.MainWindow.GetSelectedEntries() == null ||
                    phHost.MainWindow.GetSelectedEntries().Length == 0)
                return;

            WlanProfile profile = new WlanProfile();
            foreach (PwEntry entry in phHost.MainWindow.GetSelectedEntries())
            {
                if (!entry.Strings.Exists(FieldNames.SSIDHex))
                    return;

                profile.LoadFrom(phHost.Database, entry);

                if (!profile.IsValid)
                    return;
            }

            addToWindowsSep = selectedItemsMenu.DropDown.Items.Add(new ToolStripSeparator());
            addToWindows = selectedItemsMenu.DropDown.Items.Add("In Windows einfügen", null, AddEntriesToWindows);
        }

        public void RemoveExportToMenu(object sender, EventArgs e)
        {
            selectedItemsMenu.DropDownItems.Remove(addToWindows);
            selectedItemsMenu.DropDown.Items.RemoveAt(addToWindowsSep);
        }

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
    }
}
