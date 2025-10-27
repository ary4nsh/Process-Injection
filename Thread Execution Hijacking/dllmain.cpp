#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule,      // hModule: Handle to the DLL module
    DWORD  reason_for_call,                 // reason_for_call: Reason that the entry-point function is being called
    LPVOID lpReserved)                      // lpReserved: Reserved parameter; not used
{
    switch (reason_for_call)                // Evaluate the reason for the call to determine the appropriate action
    {
    case DLL_PROCESS_ATTACH:                         // If the DLL is being loaded into a process
        MessageBox(nullptr,                          // Owner window handle; nullptr means no owner
            L"Injected into the target process",     // Message to display in the message box
            L"Injected",                             // Title of the message box
            MB_OK);                                  // Type of message box (OK button)
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;   // Return TRUE to indicate successful initialization of the DLL

}