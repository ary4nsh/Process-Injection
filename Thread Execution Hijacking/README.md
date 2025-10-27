#Thread Execution Hijacking Example
A simple code example for injecting a Dynamic Link Library (DLL) into a target process using thread execution hijacking in Windows. This program demonstrates how to hijack a thread in another process to execute code, allowing for DLL injection.

##How Does It Work
1. Open Target Process: Opens the target process using its Process ID (PID) with the necessary permissions.
2. Get First Thread: Retrieves the first thread ID associated with the specified process.
3. Suspend Thread: Suspends the target thread to prepare for injection.
4. Allocate Memory: Allocates memory space within the target process to store the path of the DLL and the injection code.
5. Write DLL Path & Code: Writes the path of the specified DLL and the injection payload into the allocated memory of the target process.
6. Change Thread Context: Modifies the thread context to point to the injected code.
7. Resume Thread: Resumes the execution of the thread to run the injected code.

##Usage

Run the program using the following command:
```
.\ThreadExecutionHijacking.exe <pid> <dllpath>
```

##Example
```
.\ThreadExecutionHijacking.exe 1234 C:\path\to\your.dll
```
