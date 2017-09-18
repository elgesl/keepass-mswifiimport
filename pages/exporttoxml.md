# Export wifi informations to a .xml-file {#exporttoxml}
You can export the information of a wireless connection stored in an database entry (back) to the windows system by right click on it `Selected Entries` &rarr; `In .xml Datei exportieren`.

### Warning
- Passwords are unprotected when safed to a .xml-file!
- If the entry does not contain the valid information of a wifi connection, then context menu entry `In .xml exportieren` will not exist.

### Why do we not use the normal "Export" dialog?
I think the main reason is that I do not fully understand the KeePass Interfaces and do not find any explanatin of it.

The reason is that we cannot export *every* entry, but only quite special ones. And I do not see how I can implement this using the export system of KeePass. Furthermore, we cannot export to a single file (and I did not find any way to let the user choose a directory if I use the export system of KeePass.)
