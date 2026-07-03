#include "process_spawner.hpp"
#include "memory_sniffer.hpp"
#include "artifact_generator.hpp"
#include <iostream>
#include <unordered_set>
#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

// limit linkage visibility to this translation unit
namespace {
    void synchronise_process_maps(pid_t pid, std::unordered_set<std::string>& registry) noexcept {
        try {
            const auto current_deps = dsbom::MemorySniffer::scrape_executable_dependencies(pid);
            for (const auto& dep : current_deps) {
                // c++20 compliant substring filtering to eliminate c++23 constraints
                if (dep.find("dSBOM") == std::string::npos && registry.insert(dep).second) {
                    std::cout << "[dsbom found] -> " << dep << "\n";
                }
            }
        } catch (...) {
            // protect tracing loop from collapsing if a target process exits mid-read
        }
    }
}

void run_tracer_loop(pid_t root_pid, const std::string& target_binary) {
    int status = 0;
    std::unordered_set<std::string> global_sbom_registry;
    std::unordered_set<pid_t> active_pids = {root_pid};
    std::unordered_set<pid_t> exec_fired_pids;

    std::cout << "[*] dsbom engine: tracking hardened multi-process workload on pid " << root_pid << "\n";

    // wake up the root process to begin tracking state steps
    if (ptrace(PTRACE_SYSCALL, root_pid, nullptr, nullptr) < 0) {
        std::cerr << "[!] initial structural engine boot failed.\n";
        return;
    }

    while (!active_pids.empty()) {
        // enforce __wall to capture all thread/fork events regardless of exit signals
        const pid_t current_pid = waitpid(-1, &status, __WALL);
        if (current_pid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        active_pids.insert(current_pid);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            active_pids.erase(current_pid);
            exec_fired_pids.erase(current_pid);
            continue;
        }

        const int event = status >> 16;
        const int stop_sig = WSTOPSIG(status);

        // state machine phase 1: catch creation events instantly to beat short-lived fork races
        if (event != 0) {
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
                unsigned long new_pid_msg = 0;
                if (ptrace(PTRACE_GETEVENTMSG, current_pid, nullptr, &new_pid_msg) >= 0) {
                    const pid_t child_fork_pid = static_cast<pid_t>(new_pid_msg);
                    active_pids.insert(child_fork_pid);
                    // instantly capture maps at birth before the child runs away
                    synchronise_process_maps(child_fork_pid, global_sbom_registry);
                }
            }
            else if (event == PTRACE_EVENT_EXEC) {
                exec_fired_pids.insert(current_pid);
                if (current_pid == root_pid) {
                    global_sbom_registry.insert(target_binary);
                }
                synchronise_process_maps(current_pid, global_sbom_registry);
            }
        }
        // state machine phase 2: filter syscall traps via ptrace_o_tracesysgood (sets 0x80 bit)
        else if (stop_sig == (SIGTRAP | 0x80)) {
            if (exec_fired_pids.count(current_pid)) {
                struct user_regs_struct regs{};
                if (ptrace(PTRACE_GETREGS, current_pid, nullptr, &regs) >= 0) {
                    const long syscall_num = regs.orig_rax;
                    
                    // skip expensive /proc reads unless memory layout is directly changing
                    if (syscall_num == SYS_mmap || syscall_num == SYS_mprotect || syscall_num == SYS_execve) {
                        synchronise_process_maps(current_pid, global_sbom_registry);
                    }
                }
            }
        }

        // advance thread execution and force kernel to flag the next syscall boundary
        ptrace(PTRACE_SYSCALL, current_pid, nullptr, nullptr);
    }

    std::cout << "\n[*] target tree execution finished. hardening and analyzing static features...\n";
    
    // inspect binary disk image for embedded runtime markers (e.g., go)
    dsbom::ArtifactGenerator::inspect_and_append_static_metadata(target_binary, global_sbom_registry);
    dsbom::ArtifactGenerator::generate_cyclonedx(global_sbom_registry, "runtime-sbom.json");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <path_to_target_binary> [args...]\n";
        return EXIT_FAILURE;
    }

    const std::string target_binary = argv[1];
    
    // pre-allocate vector memory to prevent dynamic reallocations
    std::vector<std::string> target_args;
    target_args.reserve(static_cast<size_t>(argc - 2));
    for (int i = 2; i < argc; ++i) {
        target_args.push_back(argv[i]);
    }

    try {
        const pid_t target_pid = dsbom::ProcessSpawner::spawn(target_binary, target_args);
        run_tracer_loop(target_pid, target_binary);
    } catch (const std::exception& ex) {
        std::cerr << "[critical engine error]: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}