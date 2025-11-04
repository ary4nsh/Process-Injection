# VDSO Hijacking
A minimal proof-of-concept that exploits a vulnerability in a target process by injecting arbitrary shellcode into its Virtual Dynamic Shared Object (VDSO) memory space. The injector modifies the target process's memory by finding the VDSO address and overwriting it with the shellcode to execute arbitrary code within the context of the victim process.

## How it works (step-by-step)
1. Parse command line: Accept the target PID (must belong to a running process) from the user.
2. Open the device: Access a device file that allows read/write operations to the target process.
3. Leak memory address: Iteratively read through memory addresses to find the gettimeofday function to gather relevant context.
4. Check VDSO address: Retrieve the VDSO address using getauxval to determine where the shellcode should be injected.
5. Allocate memory for shellcode: Adjust the address and configure the read/write point where the shellcode will be placed.
6. Write shellcode: Inject the predetermined shellcode into the designated memory location of the target process.
7. Trigger execution: Validate the shellcode's presence in the VDSO to ensure it executes properly.
8. Clean up: Free allocated memory and close file descriptors after the injection process completes.

## Usage
```
$ ./VDSOInject <PID>
```

## Example:
```
$ ./VDSOInject 1336
```

The program will:
- Open the device file for read/write access.
- Leak memory addresses to find the target function in the VDSO.
- Validate and inject the raw shellcode into the target process’s memory.
- Check for successful injection and execute the shellcode.
- Clean up memory allocations and restore the original process state.
