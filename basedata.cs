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

using KeePassLib;
using KeePassLib.Security;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;


namespace MSWifiImportPlugin
{
    /// <summary>
    /// Each Data is safed in a AbstractData as they can be safed in a XML-file
    /// or in a Database and therefore does not only contain its value and its name
    /// in a XML-file but also a name in the database
    /// </summary>
    /// 
    public abstract class AbstractData : IXmlSerializable
    {
        /// <summary>If this is true and this is invalid, then its parent is invalid, too.</summary>
        public bool IsMandory { get; set; }

        /// <summary>Name of the value in the database</summary>
        public String EntryName { get; set; }

        /// <summary>Standard constructor</summary>
        /// <param name="eName">Name of the value in the database</param>
        /// <param name="eIsMandory">Whether the datas parent is only valid if the data is valid.</param>
        protected AbstractData(String eName, bool eIsMandory)
        {
            EntryName = eName;
            IsMandory = eIsMandory;
        }

        /// <summary>Whether the value must be written in the XML-file, i.e. its valid but not empty.</summary>
        /// <returns>Whether it is necessary.</returns>
        public abstract bool WriteNecessary
        { get; }

        /// <summary>Writes the data to a XML-file</summary>
        /// <param name="writer">The corresponding writer</param>
        public abstract void WriteXml(XmlWriter writer);

        /// <summary>Reads the data from a XML-file</summary>
        /// <param name="writer">The corresponding reader</param>
        public abstract void ReadXml(XmlReader reader);

        /// <summary>Always null</summary>
        public XmlSchema GetSchema()
        { return (null); }

        /// <summary>Checks whether the data is contained in a given entry</summary>
        /// <param name="db">The database in which the entry is safed</param>
        /// <param name="entry">The entry in which the data is (or isn't) safed.</param>
        /// <returns>Whether the data is contained in a given entry.</returns>
        public abstract bool ExistsIn(PwDatabase db, PwEntry entry);

        /// <summary>Writes a data to a given enty in a database</summary>
        /// <param name="db">The database in which the entry is safed</param>
        /// <param name="entry">The entry in which the data will be safed.</param>
        /// <returns>Whether the data is successfully saved.</returns>
        public abstract bool SaveIn(PwDatabase db, PwEntry entry);

        /// <summary>Reads a data from a given enty in a database</summary>
        /// <param name="db">The database in which the entry is safed</param>
        /// <param name="entry">The entry in which the data was saved.</param>
        /// <returns>Whether the data is successfully loaded.</returns>
        public abstract bool LoadFrom(PwDatabase db, PwEntry entry);

        /// <summary>Deletes the data from a given enty in a database</summary>
        /// <param name="db">The database in which the entry is safed</param>
        /// <param name="entry">The entry from which the data will be removed.</param>
        public abstract void ClearIn(PwDatabase db, PwEntry entry);

        /// <summary>Clears the data</summary>
        public abstract void Clear();

        /// <summary>
        /// Whether the data is valid, i.e. all mandory subentries have to valid.
        /// </summary>
        /// <returns>Whether it is valid</returns>
        public abstract bool IsValid { get; }
    }

    /// <summary>An AbstractData for a simple value, e.g. string, bool, int.</summary>
    /// <typeparam name="T">What is saved in the Data</typeparam>
    public class Data<T> : AbstractData where T : new()
    {
        /// <summary>
        /// A Function translating a string (from a .xml-file or from a db entry) to the value
        /// </summary>
        /// <param name="val">The string to be translated</param>
        /// <returns>The translated value</returns>
        public delegate T DFctFromString(ProtectedString val);

        /// <summary>
        /// A function translating the value to a string (to write it to a db entry)
        /// </summary>
        /// <param name="val">The value to be translated</param>
        /// <param name="protect">Whether the translated value has to be encrypted.</param>
        /// <returns>The translated value</returns>
        public delegate ProtectedString DFctToString(T val, bool protect);

        /// <summary>Whether the given string can be translated to a valid data</summary>
        /// <param name="val">The string to be translated</param>
        /// <returns>Whether the string can be translated</returns>
        public delegate bool DValidString(ProtectedString val);

        /// <summary>Is the value of the data is valid</summary>
        /// <param name="val">The value to be checked</param>
        /// <returns>Whether the value is valid</returns>
        public delegate bool DValidValue(T val);

        /// <summary>The <see cref="FctFromString"/> for the given data</summary>
        public DFctFromString FctFromString { get; set; }

        /// <summary>The <see cref="FctToString"/> for the given data</summary>
        public DFctToString FctToString { get; set; }

        /// <summary>The <see cref="ValidString"/> for the given data</summary>
        public DValidString FctIsValidString { get; set; }

        /// <summary>The <see cref="ValidValue"/> for the given data</summary>
        public DValidValue FctIsValid { get; set; }

        /// <summary>Standard constructor</summary>
        /// <param name="fromString"><see cref="DFctFromString"/></param>
        /// <param name="toString"><see cref="DFctToString"/></param>
        /// <param name="eName">The name in the database entry</param>
        /// <param name="eIsMandory">Whether the data is valid</param>
        /// <param name="isValidString"><see cref="DFctIsValidString"/></param>
        /// <param name="isValid"><see cref="DFctIsValid"/></param>
        public Data(DFctFromString fromString, DFctToString toString, String eName, bool eIsMandory = false,
                    DValidString isValidString = null, DValidValue isValid = null)
            : base(eName, eIsMandory)
        {
            Value = new T();
            FctFromString = fromString;
            FctToString = toString;
            FctIsValidString = isValidString;
            FctIsValid = isValid;
        }

        /// <summary> Whether a given value would be a valid one if this is set to it.</summary>
        /// <param name="val">The value to be checked.</param>
        /// <returns>Whether the value is a valid one.</returns>
        public bool IsValidValue(T val)
        { return ((FctIsValid == null) || FctIsValid(val)); }

        /// <summary> Whether a given string would give a valid value if this is set to it.</summary>
        /// <param name="val">The value to be checked.</param>
        /// <returns>Whether the value is a valid one.</returns>
        public bool IsValidValueString(ProtectedString val)
        { return ((FctIsValidString == null) || FctIsValidString(val)); }

        /// <summary>The value saved in the data</summary>
        /// Note that the setting function also resets 'isValid'.
        public T Value
        {
            get { return _value; }
            set { _value = value; LastInputValid = IsValidValue(value); }
        }
        private T _value;

        /// <summary>Whether the value was valid after setting/reading it the last time.</summary>
        protected bool LastInputValid = false;

        public override bool IsValid { get { return LastInputValid; } }

        public override bool WriteNecessary
        { get { return (IsValid && (IsMandory || !FctToString(Value, true).IsEmpty)); } }

        public override void WriteXml(XmlWriter writer)
        {
            if (WriteNecessary)
                writer.WriteString(FctToString(Value, true).ReadString());
        }

        public override void ReadXml(XmlReader reader)
        {
            reader.MoveToContent();
            reader.Read();

            FromString(new ProtectedString(true, reader.ReadContentAsString()));
        }

        /// <summary>Sets the value from a given string</summary>
        /// <param name="str">The value as string</param>
        /// <return>Whether a valid value was set.</return>
        /// Note that if a non-valid string is given, then value is cleared
        private bool FromString(ProtectedString str)
        {
            if (!IsValidValueString(str))
            {
                Clear();
                return false;
            }

            Value = FctFromString(str);
            if (!IsValidValue(Value))
            {
                Clear();
                return false;
            }
            else
            {
                LastInputValid = true;
                return true;
            }
        }

        public override bool ExistsIn(PwDatabase db, PwEntry entry)
        { return entry.Strings.Exists(EntryName); }

        public override bool SaveIn(PwDatabase db, PwEntry entry)
        {
            if (!IsValid)
                return false;

            entry.Strings.Set(EntryName, FctToString(Value, db.MemoryProtection.GetProtection(EntryName)));
            return true;
        }

        public override bool LoadFrom(PwDatabase db, PwEntry entry)
        {
            if (!ExistsIn(db, entry))
                return false;

            FromString(entry.Strings.Get(EntryName));

            return IsValid;
        }

        public override void ClearIn(PwDatabase db, PwEntry entry)
        {
            if (!ExistsIn(db, entry))
                return;
            entry.Strings.Remove(EntryName);
        }

        public override void Clear()
        {
            LastInputValid = false;
            Value = new T();
        }
    }

    /// <summary>A string data</summary>
    public class DataString : Data<ProtectedString>
    {
        /// <summary>Constructor</summary>
        /// <param name="eName">Name of the value in the database</param>
        /// <param name="eIsMandory">Whether the datas parent is only valid if the data is valid.</param>
        /// <param name="isValid"><see cref="fctIsValid"/> with T=ProtectedString</param>
        public DataString(String eName, bool eIsMandory = false, DValidValue isValid = null)
            : base((str) => { return str; }, (val, protect) => { return val.WithProtection(protect); },
                   eName, eIsMandory, null, isValid)
        { }

        /// <summary>Constructor (mandory=false=</summary>
        /// <param name="eName">Name of the value in the database</param>
        /// <param name="validValues">The value is valid if it is contained in this list</param>
        public DataString(String eName, List<String> validValues)
            : this(eName, false, validValues)
        { }

        /// <summary>Constructor</summary>
        /// <param name="eName">Name of the value in the database</param>
        /// <param name="eIsMandory">Whether the datas parent is only valid if the data is valid.</param>
        /// <param name="validValues">The value is valid if it is contained in this list</param>
        public DataString(String eName, bool eIsMandory, List<String> validValues)
            : this(eName, eIsMandory,
                   (val) =>
                   {
                       foreach (String str in validValues)
                       {
                           if (new ProtectedString(val.IsProtected, str) == val)
                               return true;
                       }
                       return false;
                   })
        { }

        /// <summary>Returns the (unprotected!) string saved in the data if the data is valid or null otherwise</summary>
        /// <returns>The unprotected string in the data or null (if this is invalid)</returns>
        public String ReadString()
        {
            if (IsValid)
                return Value.ReadString();
            return null;
        }
    }

    /// <summary>A bool data</summary>
    public class DataBool : Data<bool>
    {
        public DataBool(String eName, bool eIsMandory = false)
            : base((str) => { return (str.ReadString().ToLower() == "true"); },
                   (val, protect) => { return new ProtectedString(protect, val ? "true" : "false"); },
                   eName, eIsMandory,
                   (str) => { return ((str.ReadString().ToLower() == "true") || (str.ReadString().ToLower() == "false")); },
                   null)
        { }
    }

    /// <summary>A integer data</summary>
    public class DataInt : Data<int>
    {
        public DataInt(String eName, bool eIsMandory = false, DValidValue isValid = null)
            : base((str) => { return Int32.Parse(str.ReadString()); },
                   (val, protect) => { return new ProtectedString(protect, val.ToString()); },
                   eName, eIsMandory,
                   (str) => { int res; return Int32.TryParse(str.ReadString(), out res); },
                   isValid)
        { }
    }

    /// <summary>The data for a complex type</summary>
    /// <typeparam name="T">The complex type containing every subvalue, <see cref="Data"/></typeparam>
    public class DataData<T> : AbstractData where T : Data, new()
    {
        /// <summary>The value of the complex type</summary>
        public T Value;

        /// <summary>Standard constructor</summary>
        /// <param name="eName">A necessary value in the database</param>
        /// <param name="eIsMandory">Whether the data is necessary for the parent data</param>
        public DataData(String eName, bool eIsMandory = false)
            : base(eName, eIsMandory)
        { }

        public override bool WriteNecessary
        { get { return (Value != null) && (IsMandory || Value.IsValid); } }

        public override void WriteXml(XmlWriter writer)
        {
            if (Value != null)
                Value.WriteXml(writer);
        }

        public override void ReadXml(XmlReader reader)
        {
            if (Value == null)
                Value = new T();

            Value.ReadXml(reader);

            if (!Value.IsValid)
                Value = null;
        }

        public override bool SaveIn(PwDatabase db, PwEntry entry)
        {
            if (Value == null)
                return false;
            else
                return Value.SaveIn(db, entry);
        }

        public override bool ExistsIn(PwDatabase db, PwEntry entry)
        {
            // If T has a static method ExistsIn, then this method is used to determine whether the value
            // exists. Otherwise we use the standard method (applying EntryString).
            MethodInfo existsIn = typeof(T).GetMethod("ExistsIn", BindingFlags.Static | BindingFlags.Public);

            if (existsIn == null)
                return entry.Strings.Exists(EntryName);
            else
                return (bool)existsIn.Invoke(null, new object[] { db, entry });
        }

        public override bool LoadFrom(PwDatabase db, PwEntry entry)
        {
            if (Value == null)
                Value = new T();

            if (!ExistsIn(db, entry))
            {
                Value = null;
                return false;
            }

            if (Value.LoadFrom(db, entry))
                return true;
            else
            {
                Value = null;
                return false;
            }
        }

        public override void ClearIn(PwDatabase db, PwEntry entry)
        {
            if (!ExistsIn(db, entry))
                return;

            if (Value == null)
            {
                Value = new T();
                Value.ClearIn(db, entry);
                Value = null;
            }
            else
                Value.ClearIn(db, entry);
        }

        public override void Clear()
        {
            if (Value != null)
            {
                Value.Clear();
                Value = null;
            }
        }

        public override bool IsValid
        {
            get
            {
                if (Value == null)
                    return false;
                return Value.IsValid;
            }
        }
    }
}

