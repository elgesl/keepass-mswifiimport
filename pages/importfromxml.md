# Import wifi informations from a .xml file {#importfromxml}
You can import one wireless connection from a compatible .xml file via `File` &rarr; `Import` &rarr; `Wifi Connection manager`, `Windows Wifi Export via NetSH`.
This will create a group `WLan` (if it does not already exist) in the root group and then create one entry in this group for the imported wifi connection information.

### How to create these .xml files
One way to create these .xml files is to export them from the Windows system. To do so, we use the `netsh wlan` command, e.g. run `netsh wlan export profile key=clear` which will create one compatible .xml-file for each wifi connection saved in the Windows system.

### Warning
- Passwords are unprotected when safed to a .xml-file!

### Remarks
- Note that (so far) we do not support import to other groups.
- If there already exists an entry with the same name, i.e. its title is equal to the imported ssid, then the plugin ask whether you want it to replace the old one, rename the new one, or skip the current.
