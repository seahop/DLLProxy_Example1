This takes in a binary file and executes in memory. Tested with a Cobalt Strike .bin file and works for a PoC. Must move the 
C:\Program Files\notepad++\updater\libcurl.dll to libcurl1.dll so fowarding happens properly with this scripts current configuration.

When Notepad++ starts up, it automatically checks for an update (GUP.exe), and the proxy DLL is called, binary is searched, copied, and then executed
in memory. No AV/EDR evasion and trickery added to this, just a simple PoC.
