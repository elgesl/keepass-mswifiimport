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
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace MSWifiImportPlugin
{
    public static class WinWlan
    {
        public class SystemInterface : IDisposable
        {
            // Handle
            internal IntPtr clientHandle;
            // See WlanOpenHandle
            private uint negotiatedVersion;
            // Interfaces
            private readonly Dictionary<Guid, WlanInterface> ifaces = new Dictionary<Guid, WlanInterface>();

            public SystemInterface()
            {
                WlanOpenHandle(1, IntPtr.Zero, out negotiatedVersion, out clientHandle);
            }

            // Finalize everything
            void IDisposable.Dispose()
            {
                GC.SuppressFinalize(this);
                Close();
            }

            ~SystemInterface()
            {
                Close();
            }

            /// <summary>Close the handle</summary>
            private void Close()
            {
                if (clientHandle != IntPtr.Zero)
                {
                    WlanCloseHandle(clientHandle, IntPtr.Zero);
                    clientHandle = IntPtr.Zero;
                }
            }

            /// <summary>All WLAN interfaces</summary>
            public WlanInterface[] Interfaces
            {
                get
                {
                    IntPtr ifaceList;
                    // Enumerate the WLan Interfaces of the system
                    WlanEnumInterfaces(clientHandle, IntPtr.Zero, out ifaceList);

                    // Get the list informations
                    ListHeader header =
                        (ListHeader)Marshal.PtrToStructure(ifaceList, typeof(ListHeader));
                    Int64 listIterator = ifaceList.ToInt64() + Marshal.SizeOf(header);

                    // Will contain the results
                    WlanInterface[] interfaces = new WlanInterface[header.numberOfItems];

                    // All Guids
                    List<Guid> currentIfaceGuids = new List<Guid>();
                    for (int i = 0; i < header.numberOfItems; ++i)
                    {
                        // Information of the current interface
                        WlanInterfaceInfo info =
                            (WlanInterfaceInfo)Marshal.PtrToStructure(new IntPtr(listIterator),
                                                                      typeof(WlanInterfaceInfo));
                        listIterator += Marshal.SizeOf(info);
                        currentIfaceGuids.Add(info.interfaceGuid);

                        // Get the interface
                        WlanInterface wlanIface;
                        if (!ifaces.TryGetValue(info.interfaceGuid, out wlanIface))
                        {
                            wlanIface = new WlanInterface(this, info);
                            ifaces[info.interfaceGuid] = wlanIface;
                        }

                        interfaces[i] = wlanIface;
                    }

                    // Remove stale interfaces
                    Queue<Guid> deadIfacesGuids = new Queue<Guid>();
                    foreach (Guid ifaceGuid in ifaces.Keys)
                    {
                        if (!currentIfaceGuids.Contains(ifaceGuid))
                            deadIfacesGuids.Enqueue(ifaceGuid);
                    }
                    while (deadIfacesGuids.Count != 0)
                    {
                        Guid deadIfaceGuid = deadIfacesGuids.Dequeue();
                        ifaces.Remove(deadIfaceGuid);
                    }

                    return interfaces;
                }
            }

            [DllImport("wlanapi.dll")]
            public static extern int WlanOpenHandle(
                [In] UInt32 clientVersion,
                [In, Out] IntPtr pReserved,
                [Out] out UInt32 negotiatedVersion,
                [Out] out IntPtr clientHandle);

            [DllImport("wlanapi.dll")]
            public static extern int WlanCloseHandle(
                [In] IntPtr clientHandle,
                [In, Out] IntPtr pReserved);

            [DllImport("wlanapi.dll")]
            public static extern int WlanEnumInterfaces(
                [In] IntPtr clientHandle,
                [In, Out] IntPtr pReserved,
                [Out] out IntPtr ppInterfaceList);

            [DllImport("wlanapi.dll")]
            public static extern int WlanSetProfile(
                [In] IntPtr clientHandle,
                [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
                [In] WlanProfileFlags flags,
                [In, MarshalAs(UnmanagedType.LPWStr)] string profileXml,
                [In, Optional, MarshalAs(UnmanagedType.LPWStr)] string allUserProfileSecurity,
                [In] bool overwrite,
                [In] IntPtr pReserved,
                [Out] out int reasonCode);

            [DllImport("wlanapi.dll")]
            public static extern int WlanGetProfile(
                [In] IntPtr clientHandle,
                [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
                [In, MarshalAs(UnmanagedType.LPWStr)] string profileName,
                [In] IntPtr pReserved,
                [Out] out IntPtr profileXml,
                [Out, Optional] out WlanProfileFlags flags,
                [Out, Optional] out int grantedAccess);

            [DllImport("wlanapi.dll")]
            public static extern int WlanGetProfileList(
                [In] IntPtr clientHandle,
                [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
                [In] IntPtr pReserved,
                [Out] out IntPtr profileList
            );

            [DllImport("wlanapi.dll")]
            public static extern void WlanFreeMemory(IntPtr pMemory);

            [DllImport("wlanapi.dll")]
            public static extern int WlanDeleteProfile(
                [In] IntPtr clientHandle,
                [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
                [In, MarshalAs(UnmanagedType.LPWStr)] string profileName,
                IntPtr reservedPtr
            );
        }

        /// <summary>
        ///  Which access rights are used
        /// </summary>
        [Flags]
        public enum WlanProfileFlags
        {
            AllUser = 0,
            GroupPolicy = 1,
            User = 2,
            GetPlaintextKey = 4
        }

        /// <summary>
        /// Contains information about a LAN interface.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WlanInterfaceInfo
        {
            /// <summary>
            /// The GUID of the interface.
            /// </summary>
            public Guid interfaceGuid;
            /// <summary>
            /// Description of the interface -- we don't care.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string interfaceDescription;
            /// <summary>
            /// Current state of the interface -- we don't care.
            /// </summary>
            public int isState;
        }

        /// <summary>
        /// Header of the list returned by WlanEnumInterfaces WlanGetProfileList.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct ListHeader
        {
            public uint numberOfItems;
            public uint ind;
        }

        /// <summary>
        /// Basic information of a profile.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WlanProfileInfo
        {
            /// <summary>
            /// The name of the profile. Warning: case-sensitive.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string profileName;
            /// <summary>
            /// See WlanProfileFlags
            /// </summary>
            public WlanProfileFlags profileFlags;
        }

        /// <summary>
        /// Wlan network interface
        /// </summary>
        public class WlanInterface
        {
            /// <summary>
            /// Main access
            /// </summary>
            private readonly SystemInterface client;

            /// <summary>
            /// Information on the current lan
            /// </summary>
            private WlanInterfaceInfo info;

            internal WlanInterface(SystemInterface fclient, WlanInterfaceInfo finfo)
            {
                client = fclient;
                info = finfo;
            }

            /// <summary>
            /// Deletes a profile.
            /// </summary>
            /// <param name="profileName">
            /// Name of the profile to be deleted.
            /// </param>
            public void DeleteProfile(string profileName)
            {
                SystemInterface.WlanDeleteProfile(client.clientHandle, info.interfaceGuid, profileName, IntPtr.Zero);
            }

            /// <summary>
            /// Adds a profile.
            /// </summary>
            /// <param name="flags">The flags to set on the profile.</param>
            /// <param name="profileXml">The XML representation of the profile.</param>
            /// <param name="overwrite">Overwrite if a profile of the same name exists?</param>
            /// <returns>Success (0) or an error, see native reason code identifiers (<c>WLAN_REASON_CODE_xxx</c> identifiers).
            public int SetProfile(WlanProfileFlags flags, string profileXml, bool overwrite)
            {
                int reasonCode;
                SystemInterface.WlanSetProfile(client.clientHandle, info.interfaceGuid, flags, profileXml, null,
                                               overwrite, IntPtr.Zero, out reasonCode);
                return reasonCode;
            }

            /// <summary>XML specification of an existing profile</summary>
            /// <param name="profileName">The name of the profile.</param>
            /// <returns>The XML document.</returns>
            public string GetProfileXml(string profileName)
            {
                IntPtr profileXmlPtr;
                WlanProfileFlags flags = WlanProfileFlags.GetPlaintextKey;
                int grantedAccess;

                SystemInterface.WlanGetProfile(client.clientHandle, info.interfaceGuid, profileName, IntPtr.Zero,
                                               out profileXmlPtr, out flags, out grantedAccess);

                return Marshal.PtrToStringUni(profileXmlPtr);
            }

            /// <summary>XML specifications of all existing profiles</summary>
            /// <returns>Dictionary(ProfileInfo => XML documents)</returns>
            public Dictionary<String, String> GetProfilesXmls()
            {
                Dictionary<String, String> res = new Dictionary<String, String>();

                foreach (WlanProfileInfo profile in GetProfiles())
                    res.Add(profile.profileName, GetProfileXml(profile.profileName));

                return res;
            }

            /// <summary>All profiles on this interface</summary>
            /// <returns>A list of profile Informations</returns>
            public WlanProfileInfo[] GetProfiles()
            {
                IntPtr profileListPtr;
                SystemInterface.WlanGetProfileList(client.clientHandle, info.interfaceGuid, IntPtr.Zero, 
                                                   out profileListPtr);
                ListHeader header = (ListHeader)Marshal.PtrToStructure(profileListPtr, typeof(ListHeader));
                WlanProfileInfo[] profileInfos = new WlanProfileInfo[header.numberOfItems];

                // By the standard this is the correction start position
                long profileListIterator = profileListPtr.ToInt64() + Marshal.SizeOf(header);
                for (int i = 0; i < header.numberOfItems; ++i)
                {
                    WlanProfileInfo profileInfo
                        = (WlanProfileInfo)Marshal.PtrToStructure(new IntPtr(profileListIterator),
                                                                  typeof(WlanProfileInfo));
                    profileInfos[i] = profileInfo;
                    profileListIterator += Marshal.SizeOf(profileInfo);
                }
                return profileInfos;
            }

            /// <summary>Network interface of the given wireless interface.</summary>
            public NetworkInterface NetworkInterface
            {
                get
                {
                    foreach (NetworkInterface netIface in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        Guid netIfaceGuid = new Guid(netIface.Id);

                        if (netIfaceGuid.Equals(info.interfaceGuid))
                            return netIface;
                    }
                    return null;
                }
            }

            /// <summary>GUID of the interface (see System.Net.NetworkInformation.NetworkInterface.Id)</summary>
            public Guid InterfaceGuid
            {
                get { return info.interfaceGuid; }
            }
        }
    }
}
