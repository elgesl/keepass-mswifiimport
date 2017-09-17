# Import wifi informations from Windows {#importfromwindows}
You can import all wireless connections saved in Windows via `File` &rarr; `Import` &rarr; `Wifi Connection manager`, `Read from System`.
This will create a group `WLan` (if it does not already exist) in the root group and then create one entry in this group for each wirless connection saved in Windows.

### Remarks
- Note that (so far) we do not support import to other groups.
- If there already exists an entry with the same name, i.e. its title is equal to the imported ssid, then the plugin ask whether you want it to replace the old one, rename the new one, or skip the current.
