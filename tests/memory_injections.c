#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    // map memory with read write and execute permissions
    void* p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p != MAP_FAILED) {
        // release the memory after testing the mapping
        munmap(p, 4096);
    }
    return 0;
}