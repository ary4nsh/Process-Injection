#include <stdio.h>  
#include <stdlib.h>  
  
__attribute__((constructor))  // executed when the library is loaded into memory
void init_library() {  
    printf("Library loaded: Hello from the constructor!\n"); // direct output
    system("date >> /tmp/win"); // blind verification
}