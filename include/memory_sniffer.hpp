#pragma once

#include <string>
#include <unordered_set>
#include <sys/types.h>
#include <cstdint> // to fix the uintptr_t error

namespace dsbom {

struct MemoryMapping {
    std::string path;
    uintptr_t start_address; 
    uintptr_t end_address; 

    bool operator==(const MemoryMapping& other) const {
        return path == other.path;
    }
};

class MemorySniffer {
public:
    static std::unordered_set<std::string> scrape_executable_dependencies(pid_t pid);
};

} // namespace dsbom