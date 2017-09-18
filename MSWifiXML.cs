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
using System.Drawing;
using System.IO;

using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePass.DataExchange;
using KeePass.UI;

namespace MSWifiImportPlugin
{
    public class MSWifiXML : MSWifi
    {
        /// <summary>Jep, this is pretty much what we are doing...</summary>
        public override bool SupportsImport { get { return true; } }
        /// <summary>
        /// Nope, for several reasons we import to a specific group (although it would be better
        /// if the user could choose the group).
        /// </summary>
        public override bool ImportAppendsToRootGroupOnly { get { return false; } }
        /// <summary>As we cannot export the full database, this is false</summary>
        public override bool SupportsExport { get { return false; } }
        /// <summary>Just the name for our import module.</summary>
        public override String FormatName { get { return "Windows WiFi Export via NetSH"; } }
        /// <summary>As the name of the class implies, we use xml files</summary>
        public override String DefaultExtension { get { return "xml"; } }
        /// <summary>The icon with ".xml"</summary>
        public override Image SmallIcon { get { return Properties.Resources.B64x64_Imp_Wifi_XML.ToBitmap(); } }

        /// <summary>Read from a xml file</summary>
        /// <param name="pwStorage">The database in which the new entry is inserted</param>
        /// <param name="sInput">A stream on the xml file/entry</param>
        /// <param name="slLogger">Logger to be used</param>
        public override void Import(PwDatabase pwStorage, Stream sInput, IStatusLogger slLogger)
        {
            slLogger.SetText("Lese XML", new LogStatusType());

            XmlSerializer xml = new XmlSerializer(typeof(WlanProfile));
            WlanProfile wlan = (WlanProfile)xml.Deserialize(sInput);

            slLogger.SetText("Suche vorhandenen Gruppeneintrag", LogStatusType.Info);
            PwGroup group = GetStandardGroup(pwStorage, true);

            slLogger.SetText("Füge Eintrag hinzu", LogStatusType.Info);
            ImportTo(wlan, pwStorage, group, BehaviourForExEntry.ASK_USER, slLogger, 80, 20);
        }

        /// <summary>Writes to a xml file</summary>
        /// <param name="pwExportInfo">The information to be exported</param>
        /// <param name="sOutput">A stream to the xml file/entry</param>
        /// <param name="slLogger">Logger to be used</param>
        public override bool Export(PwExportInfo pwExportInfo, Stream sOutput, IStatusLogger slLogger)
        {
            XmlSerializer xml = new XmlSerializer(typeof(WlanProfile));
            WlanProfile curProfile = new WlanProfile();
            if (slLogger != null)
            {
                slLogger.SetText("Schreibe XML", LogStatusType.Info);
                slLogger.SetProgress(0);
            }

            double progress = 0;
            String name;
            foreach (PwEntry entry in pwExportInfo.DataGroup.GetEntries(true))
            {
                if (slLogger != null)
                {
                    name = entry.Strings.Get(PwDefs.TitleField).ReadString();
                    if ((name == null) || (name.Length == 0))
                    {
                        name = entry.Strings.Get(FieldNames.SSID).ReadString();
                        if ((name == null) || (name.Length == 0))
                            continue;
                    }

                    slLogger.SetText(String.Format("Schreibe Wifi-Information {0}", name), LogStatusType.Info);
                    progress += 50 / pwExportInfo.DataGroup.GetEntriesCount(true);
                    slLogger.SetProgress((uint)progress);
                }

                curProfile.LoadFrom(pwExportInfo.ContextDatabase, entry);
                xml.Serialize(sOutput, curProfile);
                if (slLogger != null)
                {
                    progress += 50 / pwExportInfo.DataGroup.GetEntriesCount(true);
                    slLogger.SetProgress((uint)progress);
                }
            }

            return true;
        }
    }
}
