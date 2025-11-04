# Ptrace System Call Injection
A proof-of-concept example that uses the ptrace system call to inject arbitrary shell code into a running process without creating a remote thread. This injector attaches to a target process, such as a shell or any other executable, modifies its memory to include the provided shell code, and changes the instruction pointer to execute the shell code within the context of that process. You can use pid.c source code as a test to inject the shellcode.

## How it Works (Step-by-Step)
1. Parse Command Line: Accepts the target PID as an argument.
2. Get Maximum PID: Reads /proc/sys/kernel/pid_max to determine the maximum allowable PID.
3. Attach to Target Process: Uses ptrace(PTRACE_ATTACH) to attach to the target process specified by the PID.
4. Retrieve Register State: Saves the current state of the registers using ptrace(PTRACE_GETREGS).
5. Parse Memory Maps: Opens and reads the /proc/<PID>/maps file to identify memory regions with executable permissions.
6. Inject Shell Code: Copies the raw shell code into identified executable memory using ptrace(PTRACE_POKETEXT).
7. Modify Register State: Sets the instruction pointer (RIP) to the address of the injected shell code.
8. Continue Execution: Uses ptrace(PTRACE_CONT) to resume execution of the target process, allowing the shell code to run.
9. Cleanup: The original memory mappings and registers are restored upon completion, leaving the target process in its original state.

## Usage
```
$ ./PtraceInject <PID>
```

## Example:
```
$ ./PtraceInject 1234
```

The program will:
- Attach to the target process with the specified PID,
- Parse the /proc/<PID>/maps file to identify suitable memory regions for injection,
- Inject the raw shell code into the identified executable memory region,
- Modify the target process's instruction pointer to execute the injected shell code,
- Resume the target process execution.
