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
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using System.Reflection;
using System.Collections.Generic;

using KeePassLib;
using KeePassLib.Security;

namespace MSWifiImportPlugin
{
    /// <summary>
    /// A complex type. When the data is written to/read from a .xml-file or a database
    /// entry, then each of its properties (if it is of a subclass of AbstractData) will
    /// be written/read correspondingly (and the result of the process is calculated by
    /// the process of its properties). 
    /// </summary>
    public class Data : IXmlSerializable
    {
        public XmlSchema GetSchema()
        { return (null); }

        // Writes everything in a xml file
        public void WriteXml(XmlWriter writer)
        {
            AbstractData ent;
            // Iterated through the properties
            foreach (PropertyInfo propInfo in GetType().GetProperties())
            {
                // We only care for subclasses of AbstractData
                if (!propInfo.PropertyType.IsSubclassOf(typeof(AbstractData)))
                    continue;

                // We only write valid data and if it is invalid and mandory, then
                // we cancel the write process.
                ent = (AbstractData)propInfo.GetValue(this);
                if (!ent.IsValid)
                {
                    if (ent.IsMandory)
                        break;
                    continue;
                }

                // We write only necessary data, i.e. if it is valid, non-mandory and
                // empty, then we do not write it.
                if (!ent.WriteNecessary)
                    continue;

                // Some information (as the value name in the .xml-file) can also be
                // saved in the XmlElementAttribute
                XmlElementAttribute res
                    = (XmlElementAttribute)propInfo.GetCustomAttribute(typeof(XmlElementAttribute));
                if (res != null)
                {
                    if ((res.ElementName != null) && (res.ElementName != ""))
                    {
                        if ((res.Namespace != null) && (res.Namespace != ""))
                            writer.WriteStartElement(res.ElementName, res.Namespace);
                        else
                            writer.WriteStartElement(res.ElementName);
                    }
                    else
                        writer.WriteStartElement(propInfo.Name);
                }
                else
                    writer.WriteStartElement(propInfo.Name);
                ent.WriteXml(writer);
                writer.WriteEndElement();
            }
        }

        // Reads everything from a xml file
        public void ReadXml(XmlReader reader)
        {
            // First everything has to be set to "zero"
            Clear();

            // We start within the current xml-entry
            reader.MoveToContent();
            reader.Read();

            AbstractData ent;
            var typeinfo = GetType();
            var properties = typeinfo.GetProperties();

            while (reader.NodeType == XmlNodeType.Element)
            {
                bool found = false;

                // Look for the property of the xml-subentry
                foreach (PropertyInfo propInfo in properties)
                {
                    // Ignore properties which are not AbstractDatas
                    if (!propInfo.PropertyType.IsSubclassOf(typeof(AbstractData)))
                        continue;

                    // Some information (as the value name in the .xml-file) are saved in the
                    // XmlElementAttribute
                    XmlElementAttribute res
                        = (XmlElementAttribute)propInfo.GetCustomAttribute(typeof(XmlElementAttribute));

                    String propXMLName = propInfo.Name;
                    if ((res != null) && (res.ElementName != ""))
                        propXMLName = res.ElementName;

                    // We have to care for the data in the ElementAttribute
                    if (reader.Name == propXMLName)
                    {
                        ent = (AbstractData)propInfo.GetValue(this);
                        ent.ReadXml(reader);
                        reader.ReadEndElement();
                        found = true;
                        break;
                    }
                }

                // Unsupported xml-subentries are ignored
                if (!found)
                {
                    // We have to ensure that the xml-subentry is skipped, even if itself has subentries
                    reader.MoveToContent();
                    reader.Read();
                    reader.Skip();
                    reader.ReadEndElement();
                }
            }
        }

        /// <summary>The data is valid if all mandory subentries are valid</summary>
        /// <returns>Whether the data is valid</returns>
        public virtual bool IsValid
        {
            get
            {
                AbstractData ent;
                foreach (PropertyInfo propInfo in GetType().GetProperties())
                {
                    if (!propInfo.PropertyType.IsSubclassOf(typeof(AbstractData)))
                        continue;

                    ent = (AbstractData)propInfo.GetValue(this);
                    if (ent.IsMandory && !ent.IsValid)
                        return false;
                }

                return true;
            }
        }

        /// <summary>Saves the data in an entry in a database</summary>
        /// <param name="db">The database in which the entry lies</param>
        /// <param name="entry">The entry in which the data wil be written</param>
        /// <returns>Whether the write process was successfull.</returns>
        /// <remarks>Note that all data in entry will be removed or replaced!</remarks>
        /// Note that an invalid value will never be successfull written to the db.
        public bool SaveIn(PwDatabase db, PwEntry entry)
        {
            ClearIn(db, entry);
            if (!IsValid)
                return false;

            // We just save all properties
            var typeinfo = GetType();
            AbstractData data;
            foreach (PropertyInfo propInfo in typeinfo.GetProperties())
            {
                if (!propInfo.PropertyType.IsSubclassOf(typeof(AbstractData)))
                    continue;

                data = (AbstractData)propInfo.GetValue(this);
                if (!data.SaveIn(db, entry))
                {
                    if (data.IsMandory)
                    {
                        ClearIn(db, entry);
                        return false;
                    }
                }
            }

            return true;
        }

        /// <summary>Reads the data from an entry in a database</summary>
        /// <param name="db">The database in which the entry lies</param>
        /// <param name="entry">The entry from which the data will be read</param>
        /// <returns>Whether the read process was successfull, i.e. a valid element
        /// was read.</returns>
        /// <remarks>Note that invalid read data will always be cleared.</remarks>
        public bool LoadFrom(PwDatabase db, PwEntry entry)
        {
            Clear();

            var typeinfo = GetType();
            AbstractData curEntry = null;
            foreach (PropertyInfo propInfo in typeinfo.GetProperties())
            {
                if (!propInfo.PropertyType.IsSubclassOf(typeof(AbstractData)))
                    continue;

                curEntry = (AbstractData)propInfo.GetValue(this);
                if (!curEntry.LoadFrom(db, entry))
                {
                    if (curEntry.IsMandory)
                    {
                        Clear();
                        return false;
                    }
                }
            }

            return IsValid;
        }

        /// <summary>Delete the data from an entry in a database</summary>
        /// <param name="db">The database in which the entry lies</param>
        /// <param name="entry">The entry from which the data will be erased</param>
        public void ClearIn(PwDatabase db, PwEntry entry)
        {
            var typeinfo = GetType();
            foreach (PropertyInfo propInfo in typeinfo.GetProperties())
            {
                if (!propInfo.PropertyType.IsSubclassOf(typeof(AbstractData)))
                    continue;
                ((AbstractData)propInfo.GetValue(this)).ClearIn(db, entry);
            }
        }

        /// <summary>Deletes the content saved in the data</summary>
        public void Clear()
        {
            var typeinfo = GetType();
            foreach (PropertyInfo propInfo in typeinfo.GetProperties())
            {
                if (!propInfo.PropertyType.IsSubclassOf(typeof(AbstractData)))
                    continue;
                ((AbstractData)propInfo.GetValue(this)).Clear();
            }
        }
    }

    // Which data is stored in which db-value (name)
    public static class FieldNames
    {
        public const String ConnectionType = "wifi_ConnectionType";
        public const String ConnectionMode = "wifi_ConnectionMode";
        public const String SSID = "wifi_SSID";
        public const String SSIDHex = "wifi_SSID_Hex";
        public const String SSIDPrefix = "wifi_SSID_Prefix";
        public const String SSIDPrefixHex = "wifi_SSID_Prefix_Hex";
        public const String NonBroadcast = "wifi_NonBroadcast";
        public const String EnableRandomization = "wifi_MACRandomizationEnabled";
        public const String PMKCacheMode = "wifi_PMK_CacheMode";
        public const String PMKCacheTTL = "wifi_PMK_CacheTTL";
        public const String PMKCacheSize = "wifi_PMK_CacheSize";
        public const String PreAuthMode = "wifi_PreAuthentificationMode";
        public const String Authentication = "wifi_Authentication";
        public const String AuthenticationEncryption = "wifi_Encryption";
        public const String AuthenticationUseOneX = "wifi_Authenticiation_UseOneX";
        public const String KeyType = "wifi_SharedKey_KeyType";
        public const String IsProtected = "wifi_SharedKey_Protected";
        public const String EAPAuthMode = "wifi_EAP_AuthMode";
        public const String EAPConfigType = "wifi_EAP_ConfigType";
        public const String EAPConfigBlob = "wifi_EAP_ConfigBlob";
        public const String EAPMethodType = "wifi_EAP_MethodeType";
        public const String EAPType = "wifi_EAP_Type";
        public const String EAPConfigEAP = "wifi_EAP_config_EAP";
        public const String EAPVendorType = "wifi_EAP_VendorType";
        public const String EAPVendorID = "wifi_EAP_VendorID";
        public const String EAPAuthorID = "wifi_EAP_AuthorID";
        public const String EAPFastReconnect = "wifi_EAP_FastReconnect";
        public const String EAPInnerEAPOptional = "wifi_EAP_InnerEAPOptional";
        public const String EAPEnableQuarantineChecks = "wifi_EAP_EnableQuarantineChecks";
        public const String EAPRequireCryptoBinding = "wifi_EAP_RequireCryptoBinding";
        public const String EAPDisableUserPromptForServerValidation = "wifi_EAP_DisableUserPromptServerVali";
        public const String EAPServerNames = "wifi_EAP_ServerNames";
        public const String EAPTrustedRootCA = "wifi_EAP_TrustedRootCA";
        public const String EAPConfigEAPType = "wifi_EAP_Config_Type";
        public const String EAPUseWinlogon = "wifi_EAP_UseWinlogon";
        public const String EAPPerformServerValidation = "wifi_EAP_PerformServerVali";
        public const String EAPAcceptServerName = "wifi_EAP_AcceptServerName";
        public const String EAPAllowPromptingWhenServerCANotFound = "wifi_EAP_AllowPromptingWhenServerCAnotFound";
        public const String AutoSwitch = "wifi_AutoSwitch";
        public const String KeyIndex = "wifi_KeyIndex";
        public const String PreAuthThrottle = "wifi_PreAuthThrottle";
        public const String SingleSignOnType = "wifi_SingleSignOn_Type";
        public const String SingleSignOnMaxDelay = "wifi_SingleSignOn_MaxDelay";
        public const String SingleSignOnUserBasedVirtualLan = "wifi_SingleSignOn_UserBasedVLan";
        public const String CacheUserData = "wifi_CacheUserData";
        public const String HeldPeriod = "wifi_oneX_HeldPeriod";
        public const String StartPeriod = "wifi_oneX_StartPeriod";
        public const String MaxStart = "wifi_oneX_MaxStart";
        public const String MaxAuthFailures = "wifi_oneX_MaxAuthFailures";
        public const String AuthPeriod = "wifi_oneX_AuthPeriod";
        public const String SupplicantMode = "wifi_oneX_SupplicantMode";
        public const String OuiHeaderOui = "wifi_OuiHeaderOui";
        public const String OuiHeaderType = "wifi_OuiHeaderType";
        public const String UseMSOneX = "wifi_useMSOneX";
        public const String FIPSMode = "wifi_FIPSMode";
    }
}
