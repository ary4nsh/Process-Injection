# Remote DLL Injection

A simple code example for injecting a Dynamic Link Library (DLL) into a target process on Windows. This program demonstrates the process of remote DLL injection, which allows code execution in the context of another process. Note that this technique is not commonly used today because antimalware solutions can easily detect it.

## How does it work
1. Open Target Process: Opens the target process using its Process ID (PID) with the necessary permissions.
2. Allocate Memory: Allocates memory space within the target process to store the path of the DLL.
3. Write DLL Path: Writes the path of the specified DLL into the allocated memory of the target process.
4. Create Remote Thread: Creates a remote thread in the target process that calls LoadLibraryA, effectively loading the DLL.
5. Error Handling: Provides detailed error messages for any failures during the process.

## Usage
Run the program using the following command:
```bash
.\RemoteThread.exe <pid> <dllpath>
```

# Example
```bash
.\RemoteThread.exe 1234 C:\path\to\your.dll
```
