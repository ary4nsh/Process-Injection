# APC Injection
A simple code example for injecting a Dynamic Link Library (DLL) into a target process using Asynchronous Procedure Calls (APCs) on Windows. This program demonstrates the technique of APC injection, which allows code execution in the context of another process. Note that this method may be flagged by security software and is not commonly used in legitimate applications today.

## How Does It Work
1. Open Target Process: Opens the target process using its Process ID (PID) with the necessary permissions for memory writing and operation.
2. Allocate Memory: Allocates memory space within the target process to store the path of the DLL.
3. Write DLL Path: Writes the path of the specified DLL into the allocated memory of the target process.
4. Get Process Threads: Retrieves a list of all threads in the target process.
5. Queue APC: For each thread, queues an APC that calls LoadLibraryA, which loads the DLL into the process.
6. Error Handling: Provides detailed error messages for any failures throughout the process.

## Usage
Run the program using the following command:
```
.\ApcInject.exe <pid> <dllpath>
```

## Example
```
.\ApcInject.exe 1234 C:\path\to\your.dll
```
