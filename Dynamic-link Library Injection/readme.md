# Remote DLL Injection

A simple code example for injecting a Dynamic Link Library (DLL) into a target process on Windows. This program demonstrates the process of remote DLL injection, which allows code execution in the context of another process.

## How does it work

    Open Target Process: Opens the target process using its Process ID (PID) with the necessary permissions.
    Allocate Memory: Allocates memory space within the target process to store the path of the DLL.
    Write DLL Path: Writes the path of the specified DLL into the allocated memory of the target process.
    Create Remote Thread: Creates a remote thread in the target process that calls LoadLibraryA, effectively loading the DLL.
    Error Handling: Provides detailed error messages for any failures during the process.

## Usage
Run the program using the following command:
```bash
./RemoteThread <pid> <dllpath>
```

# Example
```bash
./RemoteThread 1234 C:\path\to\your.dll
```
