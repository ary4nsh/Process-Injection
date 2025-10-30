# ListPlanting 
Inject position-independent shell-code into regedit.exe process that hosts a **SysListView32** (List-View) control by abusing the **LVM_SORTITEMS** message.  
No remote thread is created; the payload is executed **synchronously inside the GUI thread** of the target while it is sorting the list, so most AV/EDR “remote-thread” heuristics are never triggered.

## How it works
1. Start the `regedit.exe`.  
2. Find its top-level window and the child `SysListView32` that shows the key list.  
3. Open the process and allocate RWX memory with `VirtualAllocEx`.  
4. Copy the position-independent shell-code to that buffer with the **undocumented** `NtWriteVirtualMemory` (bypasses hooks on `WriteProcessMemory`).  
5. Make sure the List-View contains more than one item (otherwise the sort callback is never invoked).  
6. Send `LVM_SORTITEMS` with `lParam = shell-code address`.  
   The control immediately calls the comparator routine supplied in `lParam` (our payload) in its own context.  
7. Clean up: free the memory and terminate the `regedit.exe` process.

## Payload  
The included shell-code is crafted from message.cpp and it's assembly code is available as payload.asm. It is only a tiny demo: it loads `user32.dll`, calls `MessageBoxA` with the text “Injected!” and returns.  

## Usage
```
.\ListPlanting.exe
```

The program is supposed to spawn `regedit.exe`, inject the payload, and display a message box; however, it does not show the message box in newer versions of Windows 10 and Windows 11.

## Limitations / Detection

* Works only against processes that contain a **SysListView32** (RegEdit, TaskMgr, ProcExp, MMC snap-ins, …).  
* The List-View must own more than one item or the sort callback is never executed.  
* Modern EDR can still flag the **RWX allocation** + **cross-process write** + **window message flood**.  
* The technique is **arch-specific** – the published shell-code is 64-bit.  
* **LVM_SORTITEMS** was abused in real malware (e.g. **Carberp**, **Turla**) – signatures exist.
