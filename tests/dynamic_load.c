#include <dlfcn.h>
#include <stdio.h>

int main() {
    // open math library dynamically to test runtime discovery
    void* handle = dlopen("libm.so.6", RTLD_LAZY);
    if (handle) {
        // close the handle immediately after verification
        dlclose(handle);
    }
    return 0;
}