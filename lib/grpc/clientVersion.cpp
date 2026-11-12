#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include "uEventAnalysisToolBackend/grpc/clientVersion.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

namespace
{
// Longer than any real version; keeps junk out of the logs.
constexpr size_t maximumLength{64};
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
ClientVersion::ClientVersion(const int major,
                             const int minor,
                             const int patch) noexcept :
// NOLINTEND(bugprone-easily-swappable-parameters)
    mMajor(major),
    mMinor(minor),
    mPatch(patch)
{
}

ClientVersion::ClientVersion(const std::string_view version)
{
    auto parsed = parse(version);
    if (!parsed)
    {
        throw std::invalid_argument("Malformed client version");
    }
    *this = *parsed;
}

std::optional<ClientVersion>
ClientVersion::parse(const std::string_view version) noexcept
{
    if (version.empty() || version.size() > maximumLength)
    {
        return std::nullopt;
    }
    // The suffix, if any, starts at the first - or +.
    const auto end = version.find_first_of("-+");
    const auto core = version.substr(0, end);
    if (end != std::string_view::npos)
    {
        const auto suffix = version.substr(end + 1);
        const bool printable
            = !suffix.empty()
           && std::ranges::all_of(suffix,
                                  [](const char c)
                                  {
                                      return c > 0x20 && c <= 0x7E;
                                  });
        if (!printable){return std::nullopt;}
    }
    // Exactly three dot-separated runs of digits.
    std::array<int, 3> numbers{};
    const char *position = core.data();
    const char *const last = core.data() + core.size();
    for (size_t i = 0; i < numbers.size(); ++i)
    {
        if (i > 0)
        {
            if (position == last || *position != '.'){return std::nullopt;}
            ++position;
        }
        // from_chars takes no sign, so "-1" and "+1" fail here.
        const auto [next, error]
            = std::from_chars(position, last, numbers.at(i));
        if (error != std::errc{} || next == position){return std::nullopt;}
        position = next;
    }
    if (position != last){return std::nullopt;}
    return ClientVersion{numbers[0], numbers[1], numbers[2]};
}

std::string ClientVersion::toString() const
{
    return std::to_string(mMajor) + "." + std::to_string(mMinor)
         + "." + std::to_string(mPatch);
}

