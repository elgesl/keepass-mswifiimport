## KeePass MS Wifi Import Plugin

This is a plugin for the password manager _KeePass 2_. It allows to import the informations of the wireless connections saved in _Windows_ to _KeePass 2_ and afterwards to export these informations back to Windows. This can be used to backup the existing wireless connections or to transfer them from one Windows system to the next (and hopefully later to other systems, too).

So far the plugin is on a alpha version level, but this will change soon(ish). In particular, not all properties of wireless connections are supported. However most wireless connections should work and I will increase the number of properties supported.

## Usage of the plugin
### Installation
Just download the main .dll file (MSWifiImportPlugin.dll) and insert it in the plugin folder in your KeePass 2 installation (after closing KeePass 2). Afterwards restart KeePass 2.

### Import
You can import all wireless connections saved in Windows via `File` –> `Import` –> `Wifi Connection manager`, `Read from System`. This will create a group `WLan` in the root group and it will create one entry in this group for each wirless connection saved in Windows.

### Export
Entries saved as above can be (re-)inserted in the wireless connections saved in Windows by right click on it –> `Selected Entries` –> `In Windows einfügen`. Any existing wireless connection saved in Windows with the same name will be replaced without further notice.

## Future plans
Detailed future plans can be found in the issues, but skipping all details the future plans are
- Extend the plugin to a fully supported plugin of KeePass, e.g. include translations etc.
- Optimize the user interface, e.g. let the user choose the group we import wifi connection information to.
- Completely support everything Windows safes in the wifi connection information instead of only what we need.
- Make a second project being an analogos plugin for KeePass2Android and therefore be able to move the wifi information safely between systems etc.
