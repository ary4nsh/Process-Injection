# Process Doppelganging
A proof-of-concept implementation demonstrating the process doppelganging technique, which allows arbitrary code execution in the context of another process (typically a legitimate one) without directly creating a remote thread or invoking a visible DLL. This injector creates a section backed by a transaction, writes the payload to it, and subsequently creates a new process that uses that section for execution. The technique exploits Windows' capabilities for transaction-based file handling and memory management to execute arbitrary payloads seamlessly.

## How it Works (Step-by-Step)
1. Parse Command Line: Accepts the path to the payload file as an argument.
2. Read Payload into Memory: Loads the contents of the specified payload file into a memory buffer.
3. Load Necessary NT API Functions: Dynamically retrieves function pointers for critical NTDLL functions required for section creation and process manipulation.
4. Create a Transaction: Initializes a transaction that allows for the transient nature of file operations, which can be rolled back.
5. Create a Transacted File: Opens a transacted file to store the payload temporarily.
6. Write Payload Data: Overwrites the transacted file with the payload data, while utilizing the transaction to defer commitment.
7. Create a Memory Section: Allocates a memory section based on the transacted file, making it executable in a new process.
8. Create New Process: Launches a new process using the created section, effectively mapping the payload into its memory space for execution.
9. Calculate Entry Point: Finds the entry point of the payload using the Process Environment Block (PEB) and prepares for execution.
10. Set Process Parameters: Configures the new process's parameters, including its environment, command line, and window title.
11. Create Remote Thread: Finally, kicks off execution by creating a remote thread in the new process pointing to the payload's entry point.
12. Cleanup: Closes all handles and frees allocated resources, leaving the target process untouched.

## Usage
Run the executable from an elevated command prompt (necessary for accessing other processes):
```
C:> Doppelgang.exe <payload path>
```

## Example:
```
C:> Doppelgang.exe C:\path\to\payload.bin
```

The program will:
- Load the specified payload into memory,
- Create a transacted file and section,
- Execute the payload within the context of a new process,
- Ensure that the host process remains intact and undetected.
