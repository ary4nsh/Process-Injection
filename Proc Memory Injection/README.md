# Proc Memory Injection
A proof-of-concept tool designed for injecting a shared object (.so) into the memory of a target process without needing to create a remote thread. The injector overrides the memory mapping of the target process to execute arbitrary code, enabling the loading of the specified shared library. This method specifically targets memory regions that allow for reading and writing, thereby facilitating the injection process. As a test, you can inject malicious.so file into the process with your desired PID.

## How it Works (Step-by-Step)
1. Parse Command Line Arguments: Accepts the target process ID (PID) and the path to the shared object (.so) file.
2. Initialize Exploit Utilities: Sets up data structures to manage memory mappings and other necessary information for the target process.
3. Read Current Syscall Information: Retrieves the current state of the syscall interface for the target process, including register values.
4. Find a Writable Memory Cave: Searches the memory maps of the target process for a writable region where the library path can be injected.
5. Create ROP Chain: Constructs a Return-Oriented Programming (ROP) chain that uses existing instructions in the target process's memory to call dlopen, loading the specified .so file.
6. Write Shared Object Path: Injects the path of the .so file into the identified writable memory cave.
7. Write ROP Chain to Stack: Places the constructed ROP chain into the stack of the target process, effectively hijacking its execution flow.
8. Trigger Library Injection: When the target process executes the next instruction after the ROP chain, it will call dlopen to load and execute the injected shared library.
9. Cleanup: Frees memory allocations and restores any modified state to maintain the integrity of the target process.

## Usage
```
$ ./ProcInject <target_pid> <so_path>
```

## Example:
```
$ ./ProcInject 1234 /path/to/libexample.so
```

The program will:
- Initialize memory structures for the specified target process,
- Retrieve current syscall information and verify the state of the target,
- Search for writable memory regions and identify a suitable location for the .so path,
- Construct and inject a ROP chain into the target process’s stack,
- Execute the injected code to load the specified shared library,
- Clean up by freeing allocated resources and leaving the target process in its original state.
