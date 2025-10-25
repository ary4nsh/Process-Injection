# PE-Relocate Self-Injection

A minimal example that duplicates its own PE image into another process (here: Notepad) and starts a thread there.
No external DLL is used; the injector carries its payload in its own .reloc section and fixes all addresses at runtime.

## How it works (step-by-step)

1. Enable SeDebugPrivilege so we can open any process.
2. Decide which Notepad to start (32-bit or 64-bit) depending on the OS.
3. Create the victim process (notepad.exe) in a suspended state.
4. Map a private copy of the injector’s own image into a R/W buffer.
5. Walk the relocation table and patch every absolute address so the copy will run from the new base that will be allocated inside Notepad.
6. Allocate executable memory inside Notepad (VirtualAllocEx) and copy the relocated image there (WriteProcessMemory).
7. Start a remote thread whose entry-point is the relocated InjectionEntryPoint routine.
8. Payload simply shows a message-box (“Injection Successful”) and exits.
9. Clean up handles and free the temporary kernel32 mapping.

## Usage

Just run the executable with Administrator rights (otherwise SeDebugPrivilege will fail):
```
C:\> injector.exe
```
The program will:
- spawn the correct Notepad (32/64-bit),
- inject itself,
- pop the message-box inside Notepad’s context,
- and terminate, leaving Notepad running.
