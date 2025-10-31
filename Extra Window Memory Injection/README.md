# Extra Window Memory Injection
A minimal proof-of-concept that hijacks the tray window’s extra window memory (EWM) to execute arbitrary code inside explorer.exe without creating a remote thread or dropping a DLL.
The injector overwrites the CTray virtual-table pointer stored in the Shell_TrayWnd extra bytes, points it to a fake vtable that lives in newly-allocated memory, and sets the WndProc entry to the supplied payload.
A single WM_CLOSE message sent to the tray window is enough to make explorer call the fake WndProc and run the shell-code in its own context.
When the payload returns the original pointer is restored and the temporary allocations are released, leaving explorer in its original state.

## How it works (step-by-step)
1. Parse command line: target PID (must be explorer.exe) and raw shell-code file on disk.
2. Read the payload into memory.
3. Open explorer with PROCESS_ALL_ACCESS.
4. Find “Shell_TrayWnd” with FindWindowW.
5. Read the current CTray pointer stored in the first extra window memory slot (GetWindowLongPtrW).
6. Allocate RWX memory inside explorer and copy the shell-code there.
7. Allocate RW memory for a fake CTray object and vtable.
8. Fill the fake vtable:
– vTable  → address of the fake vtable
– AddRef / Release → copied from original
– WndProc → address of the shell-code
9. Overwrite the extra window memory with the address of the fake object (SetWindowLongPtrW).
10. Trigger execution by posting WM_CLOSE to the tray window.
11. Restore the original pointer and free the two allocations.

## Usage
Run the executable from an elevated prompt (otherwise OpenProcess on explorer fails):
```
C:> EwmInject.exe <explorer PID>
```

## Example:
```
C:> EwmInject.exe 1336 calc.bin
```

The program will:
allocate executable memory inside explorer,
copy the raw shell-code,
redirect the CTray virtual table,
post one message to make explorer execute the payload,
restore the original pointer and vanish, leaving explorer untouched.
