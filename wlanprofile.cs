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

// To understand this file, understand http://www.microsoft.com/networking/WLAN/profile/v* (where * in {1,2,3})

namespace MSWifiImportPlugin
{
    /// <summary>Contains the information of one Wifi-Connection. By c#-XML-Serialziation each subentry is a child element.</summary>
    [XmlRootAttribute("WLANProfile", Namespace = "http://www.microsoft.com/networking/WLAN/profile/v1",
IsNullable = false)]
    public class WlanProfile : Data
    {
        public String NameOrSSID
        {
            get
            {
                if (name.IsValid)
                    return name.ReadString();
                else if (ssidConfig.IsValid)
                    return ssidConfig.Value.SSID();
                else
                    return null;
            }
        }

        public DataString name { get; set; }
            = new DataString(PwDefs.TitleField, true);
        [XmlElementAttribute(IsNullable = false, ElementName = "SSIDConfig")]
        // Yes, the standard allows more than one ssidConfig, however Windows ignores everyone except
        // the first one, so we don't care either.
        public DataData<SSIDConfigData> ssidConfig { get; set; }
           = new DataData<SSIDConfigData>(null, true);
        public DataString connectionType { get; set; }
            = new DataString(FieldNames.ConnectionType, true,
                              (val) => { return (val.ReadString() == "IBSS") || (val.ReadString() == "ESS"); });
        public DataString connectionMode { get; set; }
            = new DataString(FieldNames.ConnectionMode, false,
                              (val) => { return (val.ReadString() == "auto") || (val.ReadString() == "manual"); });
        public DataBool autoSwitch { get; set; }
            = new DataBool(FieldNames.AutoSwitch, false);
        [XmlElementAttribute(ElementName = "MSM")]
        public DataData<MSMData> msm { get; set; }
            = new DataData<MSMData>(FieldNames.AuthenticationEncryption, false);

        [XmlElementAttribute(ElementName = "IHV")]
        public DataData<IHV> ihv { get; set; }
            = new DataData<IHV>(FieldNames.OuiHeaderOui, false);
        // I did not find any explanation for ../WLAN/profile/v3, but I know that macRand is part of the profile
        [XmlElementAttribute(ElementName = "MacRandomization",
            Namespace = "http://www.microsoft.com/networking/WLAN/profile/v3")]
        public DataData<MacRandData> macRand { get; set; }
            = new DataData<MacRandData>(FieldNames.EnableRandomization, false);

        public class SSIDConfigData : Data
        {
            public String SSID ()
            {
                if (IsValid)
                {
                    if (ssid.Value.name.IsValid)
                        return ssid.Value.name.ReadString();
                    else
                        return ssid.Value.hex.ReadString();
                } else
                    return null;
            }

            // Yes, the standard allows more than one ssidConfig, however Windows ignores everyone except the first one,
            // so we don't care either.
            [XmlElementAttribute(IsNullable = false, ElementName = "SSID")]
            public DataData<SSIDData<SSIDType>> ssid { get; set; }
                = new DataData<SSIDData<SSIDType>>(null, true);

            [XmlElementAttribute(IsNullable = false, ElementName = "SSIDPrefix",
                Namespace = "http://www.microsoft.com/networking/WLAN/profile/v2")]
            public DataData<SSIDData<SSIDPrefix>> ssidPrefix { get; set; }
                = new DataData<SSIDData<SSIDPrefix>>(null, false);

            static public bool ExistsIn(PwDatabase db, PwEntry entry)
            { return SSIDData<SSIDType>.ExistsIn(db, entry); }

            [XmlElementAttribute(IsNullable = false)]
            public DataBool nonBroadcast { get; set; }
                = new DataBool(FieldNames.NonBroadcast, false);

            // There two types of SSIDs and to distinguish between them we use an additonal type
            public class SSIDType
            {
                virtual public String FieldNameHex() { return FieldNames.SSIDHex; }
                virtual public String FieldNameSSID() { return FieldNames.SSID; }
            }

            public class SSIDPrefix : SSIDType
            {
                override public String FieldNameHex() { return FieldNames.SSIDPrefixHex; }
                override public String FieldNameSSID() { return FieldNames.SSIDPrefix; }
            }

            public class SSIDData<T> : Data where T : SSIDType, new()
            {
                // name or hex has to well-defined, so ExistsIn is special
                public static bool ExistsIn(PwDatabase db, PwEntry entry)
                { return (entry.Strings.Exists(new T().FieldNameHex()) || entry.Strings.Exists(new T().FieldNameSSID())); }

                // name or hex has to well-defined, so IsValid is special
                public override bool IsValid
                { get { return (name.IsValid || hex.IsValid); } }

                // Both hex and name must have 1 <= length <= 32 to be valid. If one of them is valid, then SSID is valid
                [XmlElementAttribute(IsNullable = true)]
                public DataString hex { get; set; }
                    = new DataString(new T().FieldNameHex(), false, (val) => { return !(val.IsEmpty || val.Length > 32); });

                [XmlElementAttribute(IsNullable = true)]
                public DataString name { get; set; }
                    = new DataString(new T().FieldNameSSID(), false, (val) => { return !(val.IsEmpty || val.Length > 32); });
            }
        }

        public class MSMData : Data
        {
            /* We do not support Connectivity Elements as I did not find an explanation by MS
            public DataData<ConnectivityData> connectivity
                = new DataData<ConnectivityData>(...)*/
            // Per standard security is a non-necessary value, but as it is the only value we support,
            // and MSM itself is non-necessary, we can define it to be necessary to ensure that a empty
            // MSMData element is set to null.
            [XmlElementAttribute(IsNullable = false)]
            public DataData<SecurityData> security { get; set; }
                = new DataData<SecurityData>(FieldNames.AuthenticationEncryption, true);

            static public bool ExistsIn(PwDatabase db, PwEntry entry)
            { return SecurityData.ExistsIn(db, entry); }

            public class SecurityData : Data
            {
                static public bool ExistsIn(PwDatabase db, PwEntry entry)
                { return AuthEncryptionData.ExistsIn(db, entry); }

                [XmlElementAttribute(IsNullable = false)]
                public DataData<AuthEncryptionData> authEncryption { get; set; }
                    = new DataData<AuthEncryptionData>(FieldNames.AuthenticationEncryption, true);

                [XmlElementAttribute(ElementName = "PMKCacheMode")]
                public DataString pmkCacheMode { get; set; }
                    = new DataString(FieldNames.PMKCacheMode, false,
                                    (val) => { return ((val.ReadString() == "disabled") || (val.ReadString() == "enabled")); });
                [XmlElementAttribute(ElementName = "PMKCacheTTL")]
                public DataInt pmkCacheTTL { get; set; }
                    = new DataInt(FieldNames.PMKCacheTTL, false,
                                   (val) => { return ((5 <= val) && (val <= 1400)); });
                [XmlElementAttribute(ElementName = "PMKCacheSize")]
                public DataInt pmkCacheSize { get; set; }
                    = new DataInt(FieldNames.PMKCacheSize, false,
                                   (val) => { return ((1 <= val) && (val <= 255)); });
                [XmlElementAttribute(IsNullable = false)]
                public DataString preAuthMode { get; set; }
                    = new DataString(FieldNames.PreAuthMode, false,
                                      (val) => { return (val.ReadString() == "disabled") || (val.ReadString() == "enabled"); });
                [XmlElementAttribute(IsNullable = false)]
                public DataInt preAuthThrottle { get; set; }
                    = new DataInt(FieldNames.PreAuthThrottle, false,
                                   (val) => { return (1 <= val) && (val <= 16); });
                // Thats not in the .../v1 and .../v2, but nevertheless part of the data,
                // see https://msdn.microsoft.com/en-us/library/windows/desktop/ms707348(v=vs.85).aspx
                [XmlElementAttribute(IsNullable = false)]
                public DataData<SharedKeyData> sharedKey { get; set; }
                    = new DataData<SharedKeyData>(FieldNames.KeyType, false);

                // Thats not in the .../v1 and .../v2, but nevertheless part of the data,
                // see https://msdn.microsoft.com/en-us/library/windows/desktop/ms707348(v=vs.85).aspx
                [XmlElementAttribute(IsNullable = false)]
                public DataInt keyIndex { get; set; }
                    = new DataInt(FieldNames.KeyIndex, false, (x) => { return (0 <= x) && (x <= 3); });

                // Thats not in the .../v1 and .../v2, but nevertheless part of the data,
                // see https://msdn.microsoft.com/en-us/library/windows/desktop/ms707348(v=vs.85).aspx
                // and https://msdn.microsoft.com/en-us/library/windows/desktop/ms706288(v=vs.85).aspx
                [XmlElementAttribute(IsNullable = false, ElementName = "OneX",
                    Namespace = "http://www.microsoft.com/networking/OneX/v1")]
                public DataData<OneXData> oneX { get; set; }
                    = new DataData<OneXData>(FieldNames.EAPMethodType, false);

                public class AuthEncryptionData : Data
                {
                    static public bool ExistsIn(PwDatabase db, PwEntry entry)
                    {
                        return (entry.Strings.Exists(FieldNames.Authentication)
                                && entry.Strings.Exists(FieldNames.AuthenticationEncryption));
                    }

                    [XmlElementAttribute(IsNullable = false)]
                    public DataString authentication { get; set; }
                        = new DataString(FieldNames.Authentication, true,
                                (x) =>
                                {
                                    List<String> valid = new List<String>
                                            (new String[] { "open", "shared", "WPA", "WPAPSK", "WPA2", "WPA2PSK" });
                                    return valid.Contains(x.ReadString());
                                }
                            );

                    [XmlElementAttribute(IsNullable = false)]
                    public DataString encryption { get; set; }
                        = new DataString(FieldNames.AuthenticationEncryption, true,
                                (x) =>
                                {
                                    List<String> valid = new List<String>
                                            (new String[] { "none", "WEP", "TKIP", "AES" });
                                    return valid.Contains(x.ReadString());
                                }
                            );

                    [XmlElementAttribute(IsNullable = false)]
                    public DataBool useOneX { get; set; }
                        = new DataBool(FieldNames.AuthenticationUseOneX, false);

                    [XmlElementAttribute(IsNullable = false, ElementName = "FIPSMode")]
                    public DataBool fipsMode = new DataBool(FieldNames.FIPSMode, false);
                }

                public class SharedKeyData : Data
                {
                    [XmlElementAttribute(IsNullable = false)]
                    public DataString keyType { get; set; }
                        = new DataString(FieldNames.KeyType, true,
                                (x) =>
                                {
                                    List<String> valid = new List<String>(new String[] { "networkKey", "passPhrase" });
                                    return valid.Contains(x.ReadString());
                                }
                            );

                    [XmlElementAttribute(IsNullable = false, ElementName = "protected")]
                    public DataBool isProtected { get; set; }
                        = new DataBool(FieldNames.IsProtected, true);

                    [XmlElementAttribute(IsNullable = false)]
                    public DataString keyMaterial { get; set; }
                        = new DataString(PwDefs.PasswordField, true);
                }

                // Rest unbekannt
                public class OneXData : Data
                {
                    [XmlElementAttribute(IsNullable = false)]
                    public DataBool cacheUserData { get; set; }
                        = new DataBool(FieldNames.CacheUserData, false);

                    [XmlElementAttribute(IsNullable = false)]
                    public DataInt heldPeriod { get; set; }
                        = new DataInt(FieldNames.HeldPeriod, false, (val) => { return ((1 <= val) && (val <= 3600)); });

                    [XmlElementAttribute(IsNullable = false)]
                    public DataInt authPeriod { get; set; }
                        = new DataInt(FieldNames.AuthPeriod, false, (val) => { return ((1 <= val) && (val <= 3600)); });

                    [XmlElementAttribute(IsNullable = false)]
                    public DataInt startPeriod { get; set; }
                        = new DataInt(FieldNames.StartPeriod, false, (val) => { return ((1 <= val) && (val <= 3600)); });

                    [XmlElementAttribute(IsNullable = false)]
                    public DataInt maxStart { get; set; }
                        = new DataInt(FieldNames.MaxStart, false, (val) => { return ((1 <= val) && (val <= 100)); });

                    [XmlElementAttribute(IsNullable = false)]
                    public DataInt maxAuthFailures { get; set; }
                        = new DataInt(FieldNames.MaxAuthFailures, false, (val) => { return ((1 <= val) && (val <= 100)); });

                    [XmlElementAttribute(IsNullable = false)]
                    public DataString supplicantMode { get; set; }
                        = new DataString(FieldNames.SupplicantMode, false,
                                (val) =>
                                {
                                    List<String> valid = new List<String>
                                        (new String[] { "inhibitTransmission", "includeLearning", "compliant" });
                                    return valid.Contains(val.ReadString());
                                });

                    public DataString authMode { get; set; }
                        = new DataString(FieldNames.EAPAuthMode, false,
                                (val) =>
                                {
                                    List<String> valid = new List<String>
                                        (new String[] { "machineOrUser", "machine", "user", "guest" });
                                    return valid.Contains(val.ReadString());
                                });

                    [XmlElementAttribute(IsNullable = false)]
                    public DataData<SingleSignOnData> singleSignOn { get; set; }
                        = new DataData<SingleSignOnData>(FieldNames.SingleSignOnType, false);

                    [XmlElementAttribute(IsNullable = false, ElementName = "EAPConfig")]
                    public DataData<EAPConfigData> eapConfig { get; set; }
                        = new DataData<EAPConfigData>(FieldNames.EAPMethodType, true);

                    public class SingleSignOnData : Data
                    {
                        public DataString type { get; set; }
                            = new DataString(FieldNames.SingleSignOnType, true,
                                (val) =>
                                {
                                    List<String> valid = new List<String>(new String[] { "preLogon", "postLogon" });
                                    return valid.Contains(val.ReadString());
                                });

                        public DataInt maxDelay { get; set; }
                            = new DataInt(FieldNames.SingleSignOnMaxDelay, false,
                                (val) => { return ((0 <= val) && (val <= 120)); });

                        public DataBool userBasedVirtualLan { get; set; }
                            = new DataBool(FieldNames.SingleSignOnUserBasedVirtualLan, false);
                    }

                    // See https://msdn.microsoft.com/en-us/library/windows/desktop/ms706282(v=vs.85).aspx
                    public class EAPConfigData : Data
                    {
                        // See https://msdn.microsoft.com/en-us/library/windows/desktop/bb204680(v=vs.85).aspx
                        [XmlElementAttribute(IsNullable = false, ElementName = "EapHostConfig",
                            Namespace = "http://www.microsoft.com/provisioning/EapHostConfig")]
                        public DataData<EAPHostConfigData> eapHostConfig { get; set; }
                            = new DataData<EAPHostConfigData>(FieldNames.EAPConfigType, true);
                        
                        public class EAPHostConfigData : Data
                        {
                            [XmlElementAttribute(IsNullable = false, ElementName = "EapMethod")]
                            public DataData<EAPMethodeData> eapMethode { get; set; }
                                = new DataData<EAPMethodeData>(FieldNames.EAPMethodType, true);

                            [XmlElementAttribute(IsNullable = false, ElementName = "Config",
                                Namespace = "http://www.microsoft.com/provisioning/EapHostConfig")]
                            public DataData<BaseEapMethodConfig> config { get; set; }
                                = new DataData<BaseEapMethodConfig>(FieldNames.EAPConfigType, true);

                            [XmlElementAttribute(IsNullable = false, ElementName = "ConfigBlob")]
                            public DataString configBlob { get; set; }
                                = new DataString(FieldNames.EAPConfigBlob, true);

                            public class EAPMethodeData : Data
                            {
                                [XmlElementAttribute(IsNullable = false, ElementName = "Type",
                                    Namespace = "http://www.microsoft.com/provisioning/EapCommon")]
                                public DataString type { get; set; }
                                    = new DataString(FieldNames.EAPMethodType, true);

                                [XmlElementAttribute(IsNullable = false, ElementName = "VendorType",
                                    Namespace = "http://www.microsoft.c om/provisioning/EapCommon")]
                                public DataInt vendorType { get; set; }
                                    = new DataInt(FieldNames.EAPVendorType, true);

                                [XmlElementAttribute(IsNullable = false, ElementName = "VendorId",
                                    Namespace = "http://www.microsoft.com/provisioning/EapCommon")]
                                public DataInt vendorID { get; set; }
                                    = new DataInt(FieldNames.EAPVendorID, true);

                                [XmlElementAttribute(IsNullable = false, ElementName = "AuthorId",
                                    Namespace = "http://www.microsoft.com/provisioning/EapCommon")]
                                public DataInt authorID { get; set; }
                                    = new DataInt(FieldNames.EAPAuthorID, false);
                            }

                            // See https://msdn.microsoft.com/en-us/library/windows/desktop/bb204679(v=vs.85).aspx
                            public class BaseEapMethodConfig : Data
                            {
                                [XmlElementAttribute(IsNullable = false, ElementName = "Eap",
                                    Namespace = "http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1")]
                                public DataData<EAPConfigEAPData> eap { get; set; }
                                    = new DataData<EAPConfigEAPData>(FieldNames.EAPConfigEAP, true);

                                // See https://msdn.microsoft.com/en-us/library/windows/desktop/bb204680(v=vs.85).aspx
                                public class EAPConfigEAPData : Data
                                {
                                    [XmlElementAttribute(IsNullable = false, ElementName = "Type")]
                                    public DataString type { get; set; }
                                        = new DataString(FieldNames.EAPConfigType, true);

                                    [XmlElementAttribute(IsNullable = false, ElementName = "EapType",
                                        Namespace = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1")]
                                    public DataData<EAPConfigTypeData> eapType { get; set; }
                                        = new DataData<EAPConfigTypeData>(FieldNames.EAPRequireCryptoBinding, true);

                                    public class EAPConfigTypeData : Data
                                    {
                                        [XmlElementAttribute(ElementName = "FastReconnect")]
                                        public DataBool fastReconnect { get; set; }
                                            = new DataBool(FieldNames.EAPFastReconnect);
                                        [XmlElementAttribute(ElementName = "InnerEapOptional")]
                                        public DataBool innerEapOptional { get; set; }
                                            = new DataBool(FieldNames.EAPInnerEAPOptional);
                                        [XmlElementAttribute(ElementName = "EnableQuarantineChecks")]
                                        public DataBool enableQuarantineChecks { get; set; }
                                            = new DataBool(FieldNames.EAPEnableQuarantineChecks);
                                        [XmlElementAttribute(ElementName = "RequireCryptoBinding")]
                                        public DataBool requireCryptoBinding { get; set; }
                                            = new DataBool(FieldNames.EAPRequireCryptoBinding, true);
                                        [XmlElementAttribute(IsNullable = false, ElementName = "ServerValidation")]
                                        public DataData<ServerValData> serverVal { get; set; }
                                            = new DataData<ServerValData>(FieldNames.EAPServerNames, true);
                                        [XmlElementAttribute(IsNullable = false, ElementName = "Eap",
                                            Namespace = "http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1")]
                                        public DataData<EAPTypeEapData> eap { get; set; }
                                            = new DataData<EAPTypeEapData>(FieldNames.EAPUseWinlogon, true);
                                        [XmlElementAttribute(IsNullable = false, ElementName = "PeapExtensions")]
                                        public DataData<PeapExtensionsData> peapExt { get; set; }
                                            = new DataData<PeapExtensionsData>(FieldNames.EAPPerformServerValidation);

                                        public class ServerValData : Data
                                        {
                                            [XmlElementAttribute(ElementName = "DisableUserPromptForServerValidation")]
                                            public DataBool disaUserPrompServerValid { get; set; }
                                                = new DataBool(FieldNames.EAPDisableUserPromptForServerValidation);
                                            [XmlElementAttribute(ElementName = "ServerNames")]
                                            public DataString serverNames { get; set; }
                                                = new DataString(FieldNames.EAPServerNames, true);
                                            [XmlElementAttribute(ElementName = "TrustedRootCA")]
                                            public DataString trustedRootCA { get; set; }
                                                = new DataString(FieldNames.EAPTrustedRootCA);
                                        }

                                        public class EAPTypeEapData : Data
                                        {
                                            [XmlElementAttribute(ElementName = "Type", IsNullable = false)]
                                            public DataString type { get; set; }
                                                = new DataString(FieldNames.EAPConfigEAPType);
                                            [XmlElementAttribute(ElementName = "EapType", IsNullable = false,
                                                Namespace = "http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1")]
                                            public DataData<EAPTypeEaptTypeData> eapType { get; set; }
                                                = new DataData<EAPTypeEaptTypeData>(FieldNames.EAPUseWinlogon, true);

                                            public class EAPTypeEaptTypeData : Data
                                            {
                                                [XmlElementAttribute(ElementName = "UseWinLogonCredentials")]
                                                public DataBool useWinLogon { get; set; }
                                                    = new DataBool(FieldNames.EAPUseWinlogon, true);
                                            }
                                        }

                                        public class PeapExtensionsData : Data
                                        {
                                            [XmlElementAttribute(ElementName = "PerformServerValidation",
                                                Namespace = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2")]
                                            public DataBool perfServerVal { get; set; }
                                                = new DataBool(FieldNames.EAPPerformServerValidation, true);
                                            [XmlElementAttribute(ElementName = "AcceptServerName",
                                                Namespace = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2")]
                                            public DataBool acceptServerName { get; set; }
                                                = new DataBool(FieldNames.EAPAcceptServerName, true);
                                            [XmlElementAttribute(ElementName = "PeapExtensionsV2", IsNullable = false,
                                                Namespace = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2")]
                                            public DataData<PeapExtensionsV2Data> peapExtV2 { get; set; }
                                                = new DataData<PeapExtensionsV2Data>(FieldNames.EAPAllowPromptingWhenServerCANotFound);

                                            public class PeapExtensionsV2Data : Data
                                            {
                                                [XmlElementAttribute(ElementName = "AllowPromptingWhenServerCANotFound",
                                                    Namespace = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV3")]
                                                public DataBool allowPrompServerCAnfound { get; set; }
                                                    = new DataBool(FieldNames.EAPAllowPromptingWhenServerCANotFound,
                                                        true);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public class MacRandData : Data
        {
            [XmlElementAttribute(IsNullable = false, ElementName = "enableRandomization")]
            public DataBool enabled { get; set; }
                = new DataBool(FieldNames.EnableRandomization, true);
        }

        // https://msdn.microsoft.com/en-us/library/windows/desktop/ms706977(v=vs.85).aspx
        public class IHV : Data
        {
            [XmlElementAttribute(ElementName = "OUIHeader")]
            public DataData<OuiHeaderData> ouiHeader
                = new DataData<OuiHeaderData>(FieldNames.OuiHeaderOui, true);

            [XmlElementAttribute(ElementName = "Connectivity")]
            public DataData<ConnectivityData> connectivity
                = new DataData<ConnectivityData>(FieldNames.OuiHeaderOui, false);

            [XmlElementAttribute(ElementName = "Security")]
            public DataData<IHVSecurityData> security
                = new DataData<IHVSecurityData>(FieldNames.OuiHeaderOui, false);

            public DataBool useMSOneX = new DataBool(FieldNames.UseMSOneX, false);

            public class OuiHeaderData : Data
            {
                public DataString oui = new DataString(FieldNames.OuiHeaderOui, true);
                public DataString type = new DataString(FieldNames.OuiHeaderType, true);
            }

            // Unsupported
            public class ConnectivityData : Data
            { }

            // Unsupported
            public class IHVSecurityData : Data
            { }
        }
    }
}
