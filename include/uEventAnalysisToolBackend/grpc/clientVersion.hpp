#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_CLIENT_VERSION_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_CLIENT_VERSION_HPP
#include <compare>
#include <optional>
#include <string>
#include <string_view>

namespace UEventAnalysisToolBackend::GRPC
{

/// @class ClientVersion clientVersion.hpp
/// @brief A frontend's MAJOR.MINOR.PATCH.  A trailing -pre or +build
///        suffix (e.g., Flutter's 1.2.3+45) is accepted and ignored, so
///        versions compare on the numbers alone.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class ClientVersion
{
public:
    /// @throws std::invalid_argument if version is malformed.
    explicit ClientVersion(std::string_view version);
    /// @result The version, or nothing if it is malformed.
    [[nodiscard]] static std::optional<ClientVersion>
        parse(std::string_view version) noexcept;
    /// @result MAJOR.MINOR.PATCH, without any suffix.
    [[nodiscard]] std::string toString() const;
    [[nodiscard]] auto operator<=>(const ClientVersion &) const = default;
private:
    ClientVersion(int major, int minor, int patch) noexcept;
    int mMajor{0};
    int mMinor{0};
    int mPatch{0};
};

}
#endif
