#pragma once

#include <string>
#include <unordered_set>
#include <string_view>

namespace dsbom {

class ArtifactGenerator {
public:
    // rule of zero: enforce static utility class mechanics
    ArtifactGenerator() = delete;

    static bool generate_cyclonedx(const std::unordered_set<std::string>& dependencies, std::string_view out_path);

    static void inspect_and_append_static_metadata(std::string_view binary_path, std::unordered_set<std::string>& dependencies);

private:
    [[nodiscard]] static std::string calculate_sha256(std::string_view filepath) noexcept;
    [[nodiscard]] static std::string extract_filename(std::string_view filepath) noexcept;
};

} // namespace dsbom