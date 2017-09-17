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
using System.Drawing;
using System.IO;

using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePass.DataExchange;
using KeePass.UI;

namespace MSWifiImportPlugin
{
    public class MSWifiXML : FileFormatProvider
    {
        public override bool SupportsImport { get { return true; } }
        public override bool SupportsExport { get { return true; } }
        public override String FormatName { get { return "Windows WiFi Export via NetSH"; } }
        public override String DefaultExtension { get { return "xml"; } }
        public override String ApplicationGroup { get { return "Wifi Connection manager"; } }
        public override bool ImportAppendsToRootGroupOnly { get { return false; } }
        public override Image SmallIcon { get { return Properties.Resources.B64x64_Imp_Wifi_XML.ToBitmap(); } }

        public PwEntry ExistingEntryInGroup(PwGroup inGroup, WlanProfile wlan)
        {
            ProtectedString enName;
            // Check if the entry already exists
            foreach (PwEntry en in inGroup.GetEntries(true))
            {
                // If it has no title field, then the entry will definetivly not be replaced and
                // we can ignore it
                if (!en.Strings.Exists(PwDefs.TitleField))
                    continue;

                enName = en.Strings.Get(PwDefs.TitleField).WithProtection(true);
                // First, we compare with the name field of the wifi information
                if (wlan.name.Value != null && enName == wlan.name.Value.WithProtection(true))
                    return en;

                // Then, we compare with the SSID field of the wifi information (if it is valid)
                if (wlan.ssidConfig.Value != null && wlan.ssidConfig.Value.ssid.Value != null
                    && wlan.ssidConfig.Value.ssid.Value.name != null &&
                    enName == wlan.ssidConfig.Value.ssid.Value.name.Value.WithProtection(true))
                    return en;
            }

            return null;
        }

        public PwGroup GetStandardGroup(PwDatabase pwStorage, bool askUserIfDoesntExist = true)
        {
            PwGroup group = null;

            // Search for the correct group
            foreach (PwGroup cur in pwStorage.RootGroup.GetGroups(true))
            {
                if (cur.Name == "WLan")
                    group = cur;
            }

            // We create the group if it does not exist
            if (group == null)
            {
                if (askUserIfDoesntExist)
                {
                    VistaTaskDialog vtd = new VistaTaskDialog();
                    vtd.CommandLinks = false;
                    vtd.MainInstruction = "Es existiert keine Gruppe 'WLan' in der Basisgruppe.\nSoll diese erstellt werden?";
                    vtd.SetIcon(VtdCustomIcon.Question);

                    vtd.AddButton(1, "Ja", null);
                    vtd.AddButton(0, "Nein, abbrechen", null);
                    vtd.ShowDialog();
                    if (vtd.Result != 1)
                        return null;
                }

                group = new PwGroup(true, true);
                group.Name = "WLan";
                pwStorage.RootGroup.AddGroup(group, true);
            }

            return group;
        }

        /// <summary>
        /// This defines the behaviour when we try to insert an entry which already exists.
        /// </summary>
        public enum BehaviourForExEntry
        {
            /// <summary>We ask the user.</summary>
            ASK_USER = 0,
            /// <summary>We replace the old value.</summary>
            REPLACE,
            /// <summary>We rename the new entry and inserted besides the old one.</summary>
            RENAME_NEW_ONE,
            /// <summary>We cancel the insertation.</summary>
            CANCEL_WITHOUT_ERROR,
            /// <summary>We cancel the insertation and raise an error.</summary>
            CANCEL_WITH_ERROR
        }
        /// <summary>
        /// Imports a wlan connection information to the database. If the entry already exists, then the
        /// parameter behaviour defines the behaviour
        /// </summary>
        /// <param name="wlan">The new wifi connection informations</param>
        /// <param name="pwStorage">The database in which the group lies</param>
        /// <param name="group">The group to which we add the entry</param>
        /// <param name="behaviour">What do we do if the entry already exists?</param>
        /// <param name="slLogger">Where we log to (can be null)</param>
        /// <param name="totalProcents">If we parsed completely, how many (additional) procents of the
        /// total progress did we finish? (Senseless if slLogger = null)</param>
        /// <param name="minProcents">How many procents of the total progress were already finished</param>
        /// <returns>A map Wifi name => Wifi-connection information</returns>
        /// <remarks>Note that minProcents + totalProcents has to be less than or equal to 100.</remarks>
        /// <returns>The entry created or null if an error occured</returns>
        public PwEntry ImportTo(WlanProfile wlan, PwDatabase pwStorage, PwGroup group,
                                BehaviourForExEntry behaviour = BehaviourForExEntry.ASK_USER,
                                IStatusLogger slLogger = null, double totalProcents = 60,
                                double minProcents = 20 )
        {
            slLogger.SetProgress((uint)minProcents);
            PwEntry entry = null;

            String wlanName = wlan.NameOrSSID;// Note that the entries base name must be unprotected!
            if ((wlanName == null) || (wlanName == ""))
                return null;

            entry = ExistingEntryInGroup(group, wlan);
            if (slLogger != null)
            {
                minProcents += totalProcents / 3.0;
                slLogger.SetProgress((uint)minProcents);
            }

            // Entry exists
            if (entry != null)
            {
                if (behaviour == BehaviourForExEntry.ASK_USER)
                {
                    VistaTaskDialog vtd = new VistaTaskDialog();
                    vtd.CommandLinks = false;
                    //            vtd.Content = strDatabase;
                    vtd.MainInstruction = String.Format("Es ist bereits ein Eintrag namens {0} vorhanden.\n" +
                        "Soll der alte Eintrag durch die ausgelesenen Daten ersetzt werden oder " +
                        "ein neuer Eintrag erstellt werden?", wlan.name.Value.ReadString());
                    vtd.SetIcon(VtdCustomIcon.Question);
                    //            vtd.VerificationText = KPRes.DialogNoShowAgain;
                    //            vtd.WindowTitle = KeePass.UI. UIExtExt.ProductName;

                    vtd.AddButton((int)BehaviourForExEntry.REPLACE, "Ersetzen", null);
                    vtd.AddButton((int)BehaviourForExEntry.RENAME_NEW_ONE, "Neuer Eintrag", null);
                    vtd.AddButton((int)BehaviourForExEntry.CANCEL_WITHOUT_ERROR, "Abbrechen", null);
                    vtd.ShowDialog();
                    behaviour = (BehaviourForExEntry)vtd.Result;
                }

                switch (behaviour)
                {
                    case BehaviourForExEntry.CANCEL_WITHOUT_ERROR:
                        if (slLogger != null)
                        {
                            minProcents += 2.0 * totalProcents / 3.0;
                            slLogger.SetProgress((uint)minProcents);
                        }
                        return null;
                    case BehaviourForExEntry.CANCEL_WITH_ERROR:
                        if (slLogger != null)
                        {
                            slLogger.SetText("Fehler beim Einfügen des Eintrags", LogStatusType.Error);
                            minProcents += 2.0 * totalProcents / 3.0;
                            slLogger.SetProgress((uint)minProcents);
                        }
                        return null;
                    case BehaviourForExEntry.REPLACE:
                        group.Entries.Remove(entry);
                        entry = null;
                        break;
                    case BehaviourForExEntry.RENAME_NEW_ONE:
                        int number = 2;
                        do
                        {
                            wlan.name.Value = new ProtectedString(false, String.Format("{0} ({1})", wlanName, number));
                            entry = ExistingEntryInGroup(group, wlan);
                            ++number;
                        } while (entry != null);
                        break;
                }
            }

            entry = new PwEntry(true, true);
            if (slLogger != null)
            {
                minProcents += totalProcents / 3.0;
                slLogger.SetProgress((uint)minProcents);
            }

            if (wlan.SaveIn(pwStorage, entry))
                group.AddEntry(entry, true);
            else
                entry = null;

            if (slLogger != null)
            {
                minProcents += totalProcents / 3.0;
                slLogger.SetProgress((uint)minProcents);
            }

            // We might have change the name, so let us change it back.
            // Note again that the name must be unprotected!
            wlan.name.Value = new ProtectedString(false, wlanName);
            return entry;
        }

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
