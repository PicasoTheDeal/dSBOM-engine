#include "process_spawner.hpp"
#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <system_error>

namespace dsbom {

pid_t ProcessSpawner::spawn(const std::string& binary_path, const std::vector<std::string>& args) {
    pid_t pid = fork();

    if (pid < 0) {
        throw std::system_error(errno, std::generic_category(), "Failed to fork target process");
    }

    if (pid == 0) {
        // child process context
        
        // let the parent process trace this child
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
            std::cerr << "Child: Critical ptrace(PTRACE_TRACEME) failed.\n";
            _exit(EXIT_FAILURE);
        }

        // halt the child execution so the parent can attach and set options
        raise(SIGSTOP);

        // set up the arguments array for execvp
        std::vector<char*> c_args;
        c_args.reserve(args.size() + 2);
        c_args.push_back(const_cast<char*>(binary_path.c_str()));
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);

        execvp(binary_path.c_str(), c_args.data());

        // if execvp hits this point it means it failed completely
        std::cerr << "Child: execvp failed to execute target binary.\n";
        _exit(EXIT_FAILURE);
    }

    // parent process context
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        throw std::system_error(errno, std::generic_category(), "Failed waiting for initial child SIGSTOP");
    }

    if (!WIFSTOPPED(status)) {
        throw std::runtime_error("Child process did not stop cleanly on initialization");
    }

    // configure extended tracing and isolate syscall signals cleanly via tracesysgood
    long options = PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | 
                   PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD;
                   
    if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, options) < 0) {
        throw std::system_error(errno, std::generic_category(), "Failed to configure dynamic tracking options");
    }

    return pid;
}

} // namespace dsbom