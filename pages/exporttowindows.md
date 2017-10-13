# Export wifi information to Windows {#exporttowindows}
You can export the information of a wireless connection stored in an database entry (back) to the windows system by right click on it `Selected Entries` &rarr; `In Windows einf&uuml;gen`.

### Warning
- If the windows system already knows a wifi connection with the same ssid, then this old information is deleted before inserting the new one!
- If the entry does not contain the valid information of a wifi connection, then context menu entry `In Windows einf&uuml;gen` will not exist.

### Why do we not use the normal "Export" dialog?
I think the main reason is that I do not fully understand the KeePass Interfaces and do not find any explanatin of it.

The reason is that we cannot export *every* entry, but only quite special ones. And I do not see how I can implement this using the export system of KeePass.

### Help: It does not show the `In Windows einf&uuml;gen` entry. What can I do?
First, check whether you actually had only compatbile entries selected, i.e. generated by this plugin. If that is the case, check the entries. There was a version of the program where
the following misstakes happend:
- the fields `wifi_ConnectionMode` and `wifi_ConnectionType` were called `ConnectionMode` and `ConnectionType`. If that is the case, rename those fields.
- Check whether the field `wifi_SSID` has the exactly same value as the name of entry. This cannot be changed!

You can check the entries mentioned above by double click on the entry and then choosing `Advanced`. I am very sorry, if there is any problem arising from the version mentioned above.

If this does not help, please help my to fix the problem by sending me the problematic entry (please remove the passkeys)!