# Main page {#mainpage}
### Introduction
This is a plugin for the password manager [KeePass 2.*](http://keepass.info/). It allows to import the informations of the wireless connections saved in Windows to [KeePass 2](http://keepass.info/) and afterwards to export these informations back to Windows. This can be used to backup the existing wireless connections or to transfer them from one Windows system to the next (and hopefully later to other systems, too).

### About the plugin
The [source code of the plugin](https://github.com/elgesl/keepass-mswifiimport/) is accessable via [git](https://git-scm.com/) on https://github.com/elgesl/keepass-mswifiimport.git. The github basis is https://github.com/elgesl/keepass-mswifiimport and its github page https://elgesl.github.io/keepass-mswifiimport/.

### Current version
So far the plugin is on a alpha version level, but this will change soon(ish). In particular, not all properties of wireless connections are supported. However most wireless connections should work and I will increase the number of properties supported.

### Usage of the plugin
- [Installation](./install.html)
- [Import the informations of all wifi connection in the Windows system](./importfromwindows.html)
- [Export the information of one wifi connection into the Windows system](./exporttowindows.html)
- [Import the information of one wifi connection stored in a compatible .xml-file](./importfromxml.html)
- [Export the information of one wifi connection to a compatible .xml-file](./exporttoxml.html)

### A remark on the imported entries and supported .xml-files
You have to be quite carefull with editing these entries as they have to stay _valid_. The real definition of _valid_ is thereby non-trivial and will be published soon(ish).
The same is true for the supported .xml-files.

### Future plans
Detailed future plans can be found in the [issues](https://github.com/elgesl/keepass-mswifiimport/issues), but (skipping all details) the future plans are
- Extend the plugin to a fully supported plugin of KeePass, e.g. include translations, let the user choose the group we import data to, use the export system of KeePass, etc. Help would be really, really appreciated!
- Optimize the user interface, e.g. let the user choose the group we import wifi connection information to.
- Completely support everything Windows safes in the wifi connection information instead of only what we need.
- Make a second project being an analogos plugin for KeePass2Android and therefore be able to move the wifi information safely between systems etc.
