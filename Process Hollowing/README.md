# Process-Hollowing
A simple Process Hollowing technique code that works for old Windows 10 versions. This program demonstrates a technique called process hollowing, which replaces the code of a suspended process with the code of another executable.

## How does it work
1. Create Suspended Process: It creates the target process in a suspended state.
2. Set Current Directory: Changes the current directory to the directory where the executable is located.
3. Open Replacement Executable: Opens the specified executable file for reading.
4. Allocate Memory in Target Process: Allocates memory space in the target process to map in the replacement executable.
5. Rebase the Replacement Image: Adjusts the image base to fit into the target process’s address space.
6. Map Replacement Executable: Maps the replacement executable into the address space of the target process.
7. Copy Required Sections: Writes the header and necessary sections from the replacement executable into the target process.
8. Update PEB: Updates the Process Environment Block (PEB) with the new image base of the replacement executable.
9. Set Thread Context: Modifies the context of the target process’s thread to point to the entry point of the replacement executable.
10. Resume Execution: Resumes the execution of the target process after hollowing it.

## Usage
```
.\Hollow.exe <image_name> <replacement_exe>
```
