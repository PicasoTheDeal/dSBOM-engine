#pragma once

#include <string>
#include <vector>
#include <sys/types.h>

namespace dsbom {

class ProcessSpawner {
public:
    // spawns target application under ptrace containment
    static pid_t spawn(const std::string& binary_path, const std::vector<std::string>& args);
};

} // namespace dsbom