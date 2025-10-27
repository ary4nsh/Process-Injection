# Thread Local Storage
This program demonstrates Thread Local Storage (TLS) injection by embedding its payload directly into the TLS callbacks of a selected process, specifically targeting notepad.exe. The injector self-injects without the need for external libraries or DLLs, ensuring a seamless and effective method for code execution. Note that this injection technique is being detected by modern antivirus and security solutions.

## How It Works (Step-by-Step)
1. TLS Callback Definition: Defines a callback function (TLSCallbacks) that will trigger upon loading or unloading the injector DLL.
2. Architecture-Dependent Settings: Utilizes linker directives and segment declarations specific to the architecture (x86 or x64) to accommodate TLS callback functions.
3. Process Identification: The program finds the process ID of notepad.exe by creating a snapshot of running processes and comparing their executable names.
4. Process Handle Opening: Requests a handle to the identified Notepad process with appropriate permissions to allow for memory manipulation.
5. Memory Allocation: Allocates executable memory in the Notepad process using VirtualAllocEx to accommodate the injected payload.
6. Payload Injection: Writes the payload into the allocated memory space using WriteProcessMemory.
7. Thread Creation: Employs CreateRemoteThread to execute the payload in the context of the target process via the TLS callback.
8. Injection Confirmation: Displays a message box in Notepad confirming successful injection.
9. Resource Cleanup: Ensures that all handles are properly closed and resources are freed.

## Usage
To execute this program, ensure you run it with Administrator privileges. This can be done by right-clicking the executable and selecting "Run as Administrator." Use the following command line:
```
C:\> TlsInject.exe
```

When executed, the program will:
- Search for a running instance of Notepad,
- Perform the injection of its payload into Notepad's TLS,
- Show a message box indicating successful injection,
- Terminate after the injection, leaving Notepad operational and unaffected.
