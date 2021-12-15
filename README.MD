This takes in a binary file and executes in memory. Tested with a Cobalt Strike .bin file and works for a PoC. Must move the 
C:\Program Files\notepad++\updater\libcurl.dll to libcurl1.dll so fowarding happens properly with this scripts current configuration.

When Notepad++ starts up, it automatically checks for an update (GUP.exe), and the proxy DLL is called, binary is searched, copied, and then executed
in memory. No AV/EDR evasion and trickery added to this, just a simple PoC.

To create your own, pull back the DLL you wish to proxy, use VS Native Tools Command prompt on the DLL (dumpbin /exports nameof.dll), and map them in order with ordinal (ex. @1, @2, etc). Depending on how many exports the DLL has, it can be quite a lengthy process getting them in order but it is scriptable:
#pragma comment(linker, "/export:curl_easy_cleanup=libcurl1.curl_easy_cleanup,@1")
