#include <unistd.h>

int main() {
    // flood the kernel with syscalls to test tracer performance
    for(int i = 0; i < 5000; i++) {
        getpid();
    }
    return 0;
}