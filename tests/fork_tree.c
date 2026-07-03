#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <dlfcn.h>

int main() {
    // spawn the first background child process
    pid_t child_pid = fork();

    if (child_pid < 0) {
        return EXIT_FAILURE;
    }

    if (child_pid == 0) {
        // inside first child context - fork again to create a grandchild
        pid_t grandchild_pid = fork();

        if (grandchild_pid < 0) {
            return EXIT_FAILURE;
        }

        if (grandchild_pid == 0) {
            // inside grandchild context - dynamically load the math library mid-flight
            void* handle = dlopen("libm.so.6", RTLD_NOW);
            if (!handle) {
                return EXIT_FAILURE;
            }

            // use the posix compliant casting trick to bypass iso c pedantic warnings
            double (*cos_func)(double);
            *(void **) (&cos_func) = dlsym(handle, "cos");
            
            if (cos_func) {
                volatile double res = cos_func(1.0);
                (void)res;
            }

            dlclose(handle);
            return EXIT_SUCCESS;
        }

        // wait for grandchild to exit completely
        waitpid(grandchild_pid, NULL, 0);
        return EXIT_SUCCESS;
    }

    // wait for first child to exit completely
    waitpid(child_pid, NULL, 0);
    return EXIT_SUCCESS;
}