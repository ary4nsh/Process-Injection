#include <stdio.h>
#include <Windows.h>

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

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        printf("Usage: RemoteThread <pid> <dllpath>\n");
        return 0;
    }

    int pid = atoi(argv[1]); // convert pid to an integer

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, // Allows writing to the process's memory | Allows memory operations | Allows creating threads in the process
        FALSE,                  // Handle is not inheritable by child processes
        pid                     // The process ID of the target process
    );
    if (!hProcess) {
        PrintError("Error opening process");
        return 1;
    }

    // Allocate memory into the target process to write the path of dll to the target process
    void* buffer = VirtualAllocEx(
        hProcess,                   // hProcess: Handle to the process in which memory will be allocated
        nullptr,                    // lpAddress: Pointer to the starting address for allocation (nullptr for automatic)
        1 << 12,                    // dwSize: Size of memory to allocate (4 KB or one page)
        MEM_COMMIT | MEM_RESERVE,   // flAllocationType: Commit memory to make it accessible | Reserve the memory address range
        PAGE_READWRITE              // flProtect: Memory protection attribute allowing read and write access
    );
    if (!buffer) {
        PrintError("Failed to allocate memory into the target process");
        return 1;
    }

    // Write the dll path to memory of the target process
    if (!WriteProcessMemory(
        hProcess,             // hProcess: Handle to the target process where memory will be written
        buffer,               // lpBaseAddress: Pointer to the address in the target process's memory
        argv[2],              // lpBuffer: Pointer to the data to be written (from the second command-line argument)
        strlen(argv[2]),      // dwSize: Number of bytes to write (length of the data)
        nullptr               // lpNumberOfBytesWritten: Pointer to a variable to receive the number of bytes written (nullptr if not needed)
    )) {
        PrintError("Failed to write memory");
        return 1;
    }

    // Create a thread in target process and instruct it to load the dll
    HANDLE hThread = CreateRemoteThread(
        hProcess,                                 // hProcess: Handle to the target process in which the thread will be created
        nullptr,                                  // lpThreadAttributes: Pointer to security attributes (nullptr for default)
        0,                                        // dwStackSize: Initial stack size for the new thread (0 for default size)
        (LPTHREAD_START_ROUTINE)GetProcAddress(   // lpStartAddress: Pointer to the function to execute (LoadLibraryA in this case)
            GetModuleHandle(L"kernel32"),             // hModule: Handle to the module containing the function
            "LoadLibraryA"),                          // lpProcName: Name of the function to call
        buffer,                                   // lpParameter: Pointer to the parameter to pass to the function (address of the DLL name)
        0,                                        // dwCreationFlags: Creation flags (0 for default behavior)
        nullptr                                   // lpThreadId: Pointer to a variable to receive the thread identifier (nullptr if not needed)
    );
    if (!hThread) {
        PrintError("Failed to create remote thread");
        return 1;
    }
    printf("Remote thread created successfully!");

    return 0;
}
