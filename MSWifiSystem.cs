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
using System.Collections.Generic;
using System.Windows.Forms;

using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePass.DataExchange;
using KeePass.UI;

namespace MSWifiImportPlugin
{
    public class MSWifiSystem : MSWifi
    {
        /// <summary>Jep, this is pretty much what we are doing...</summary>
        public override bool SupportsImport { get { return true; } }
        /// <summary>
        /// Nope, for several reasons we import to a specific group (although it would be better
        /// if the user could choose the group).
        /// </summary>
        public override bool ImportAppendsToRootGroupOnly { get { return false; } }
        /// <summary>No, this does not need a file as we directly read from the system</summary>
        public override bool RequiresFile { get { return false; } }
        /// <summary>As we cannot export the full database, this is false</summary>
        public override bool SupportsExport { get { return false; } }
        /// <summary>Just the name for our import module.</summary>
        public override String FormatName { get { return "Read from system"; } }
        /// <summary>We do not use files...</summary>
        public override String DefaultExtension { get { return null; } }
        /// <summary>Just our name</summary>
        public override String ApplicationGroup { get { return "Wifi Connection manager"; } }
        /// <summary>The icon without ".xml"</summary>
        public override Image SmallIcon { get { return Properties.Resources.B64x64_Imp_Wifi.ToBitmap(); } }

        /// <summary>Reads all Wifi Profiles saved in the system (for any interface)</summary>
        /// <param name="slLogger">Where we log to (can be null)</param>
            /// <param name="totalProcents">If we parsed completely, how many (additional) procents of the
        /// total progress did we finish? (Senseless if slLogger = null)</param>
        /// <param name="minProcents">How many procents of the total progress were already finished</param>
        /// <returns>A map Wifi name => Wifi-connection information</returns>
        /// <remarks>Note that minProcents + totalProcents has to be less than or equal to 100.</remarks>
        public Dictionary<String, WlanProfile> GetSystemProfiles(IStatusLogger slLogger = null,
                    double totalProcents = 100, double minProcents = 0)
        {
            WinWlan.SystemInterface systemInterface = new WinWlan.SystemInterface();
            if (systemInterface.Interfaces.Length == 0)
                return null;

            XmlSerializer xml = new XmlSerializer(typeof(WlanProfile));
            Dictionary<String, String> xmls = null;
            Dictionary<String, WlanProfile> res = new Dictionary<String, WlanProfile>();

            StringReader reader;
            WlanProfile curProfile = null;
            foreach (WinWlan.WlanInterface wlanInterface in systemInterface.Interfaces)
            {
                xmls = wlanInterface.GetProfilesXmls();

                if (slLogger != null)
                {
                    minProcents += totalProcents / 2 / systemInterface.Interfaces.Length;
                    slLogger.SetProgress((uint)minProcents);
                }

                foreach (KeyValuePair<String, String> pair in xmls)
                {
                    reader = new StringReader(pair.Value);
                    curProfile = (WlanProfile)xml.Deserialize(reader);

                    if (curProfile.IsValid)
                        res[pair.Key] = curProfile;

                    if (slLogger != null)
                    {
                        minProcents += totalProcents / 2 / systemInterface.Interfaces.Length / xmls.Count;
                        slLogger.SetProgress((uint)minProcents);
                    }
                }
            }

            return res;
        }

        /// <summary>Read from a xml file</summary>
        /// <param name="pwStorage">The database in which the new entry is inserted</param>
        /// <param name="sInput">A stream on the xml file/entry</param>
        /// <param name="slLogger">Logger to be used</param>
        public override void Import(PwDatabase pwStorage, Stream sInput, IStatusLogger slLogger)
        {
            slLogger.SetText("Lese Systeminformationen", LogStatusType.Info);
            slLogger.SetProgress(0);
            Dictionary<String, WlanProfile> res = GetSystemProfiles(slLogger, 0.0, 15.0);

            slLogger.SetText("Suche vorhandene Gruppen", LogStatusType.Info);
            MSWifiXML xmlImporter = new MSWifiXML();
            PwGroup group = xmlImporter.GetStandardGroup(pwStorage, true);

            double progress = 20.0;
            slLogger.SetProgress((uint)progress);

            foreach (KeyValuePair<String, WlanProfile> pair in res)
            {
                slLogger.SetText(String.Format("Füge Eintrag '{0}' hinzu", pair.Key), LogStatusType.Info);

                if (null != xmlImporter.ImportTo(pair.Value, pwStorage, group,
                                                 MSWifiXML.BehaviourForExEntry.ASK_USER,
                                                 slLogger, 75.0 / res.Count, progress))
                {
                    slLogger.SetText(String.Format("Füge Eintrag '{0}' hinzu. Erfolgreich!", pair.Key),
                                     LogStatusType.Info);
                }
                else
                {
                    slLogger.SetText(String.Format("Füge Eintrag '{0}' hinzu. Fehlgeschlagen!", pair.Key),
                                     LogStatusType.Error);
                }
            }

            slLogger.SetText("Schließe ab", new LogStatusType());
            slLogger.SetProgress(100);
        }
    }
}
