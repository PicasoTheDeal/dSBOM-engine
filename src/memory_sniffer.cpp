#include "memory_sniffer.hpp"
#include <fstream>
#include <sstream>
#include <iostream>

namespace dsbom {

std::unordered_set<std::string> MemorySniffer::scrape_executable_dependencies(pid_t pid) {
    std::unordered_set<std::string> unique_dependencies;
    
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps_file(maps_path);
    
    if (!maps_file.is_open()) {
        // target process might be dead already so just handle it clean instead of throwing
        return unique_dependencies;
    }

    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string address_range, perms, offset, dev, inode;
        std::string path;

        // map structure format: 77f6b9600000-77f6b9628000 r-xp 00000000 08:02 14434257 /usr/lib/libc.so
        if (!(iss >> address_range >> perms >> offset >> dev >> inode)) {
            continue; 
        }

        // grab active executable blocks only (r-xp) to catch shared libraries or native injected payloads
        if (perms.size() >= 3 && perms[0] == 'r' && perms[2] == 'x') {
            // parse out the file path if it exists and skip any anonymous allocations without files
            if (iss >> std::ws && std::getline(iss, path)) {
                if (!path.empty() && path[0] == '/') { 
                    unique_dependencies.insert(path);
                }
            }
        }
    }

    return unique_dependencies;
}

} // namespace dsbom