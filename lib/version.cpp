#include <string>
#include "uEventAnalysisToolBackend/version.hpp"

using namespace UEventAnalysisToolBackend;

int Version::getMajor() noexcept
{
    return uEventAnalysisToolBackend_MAJOR;
}

int Version::getMinor() noexcept
{
    return uEventAnalysisToolBackend_MINOR;
}

int Version::getPatch() noexcept
{
    return uEventAnalysisToolBackend_PATCH;
}

//NOLINTBEGIN(bugprone-easily-swappable-parameters)
bool Version::isAtLeast(const int major, const int minor,
                        const int patch) noexcept
//NOLINTEND(bugprone-easily-swappable-parameters)
{
    if (uEventAnalysisToolBackend_MAJOR < major){return false;}
    if (uEventAnalysisToolBackend_MAJOR > major){return true;}
    if (uEventAnalysisToolBackend_MINOR < minor){return false;}
    if (uEventAnalysisToolBackend_MINOR > minor){return true;}
    if (uEventAnalysisToolBackend_PATCH < patch){return false;}
    return true;
}

std::string Version::getVersion() noexcept
{
    std::string version{uEventAnalysisToolBackend_VERSION};
    return version;
}

std::string Version::getTag() noexcept
{
    std::string tag{uEventAnalysisToolBackend_GITTAG};
    return tag;
}

std::string Version::getVersionWithTag() noexcept
{
    auto tag = Version::getTag();
    if (tag.empty())
    {
        return Version::getVersion();
    }
    else
    {
        return Version::getVersion() + "-" + tag;
    }
}
