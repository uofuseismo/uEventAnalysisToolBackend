#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth::Password;

class HasherOptions::HasherOptionsImpl
{
public:
    OperationsLimit mOperationsLimit{OperationsLimit::Interactive};
    size_t mMemoryLimitInBytes{67108864};
};

/// Constructor
HasherOptions::HasherOptions() :
    pImpl(std::make_unique<HasherOptionsImpl> ())
{
}

/// Copy constructor
HasherOptions::HasherOptions(const HasherOptions &options)
{
    *this = options;
}

/// Move constructor 
HasherOptions::HasherOptions(HasherOptions &&options) noexcept
{
    *this = std::move(options);
}

/// Copy assignment
HasherOptions& HasherOptions::operator=(const HasherOptions &options)
{
    if (&options == this){return *this;}
    pImpl = std::make_unique<HasherOptionsImpl> (*options.pImpl);
    return *this;
}

/// Move assignment
HasherOptions& HasherOptions::operator=(HasherOptions &&options) noexcept
{
    if (&options == this){return *this;}
    pImpl = std::move(options.pImpl);
    return *this;
}
 
/// Destructor
HasherOptions::~HasherOptions() = default;

/// Ops limit
void HasherOptions::setOperationsLimit(const OperationsLimit limit) noexcept
{
    pImpl->mOperationsLimit = limit;
}

HasherOptions::OperationsLimit HasherOptions::getOperationsLimit() const noexcept
{
    return pImpl->mOperationsLimit;
}

/// Memory limit
void HasherOptions::setMemoryLimitInBytes(const size_t limit)
{
    if (limit < 8192)
    {
        throw std::invalid_argument("Memory limit must be at least 8192");
    }
    pImpl->mMemoryLimitInBytes = limit;
}

size_t HasherOptions::getMemoryLimitInBytes() const noexcept
{
    return pImpl->mMemoryLimitInBytes;
}

HasherOptions HasherOptions::fromInitializationFile(
    const std::filesystem::path &iniFile,
    const std::string &sectionIn)
{
    if (!std::filesystem::exists(iniFile))
    {
        throw std::invalid_argument("Initialization " + std::string{iniFile}
                                  + " file does not exist");
    }
    // Make sure section ends with . so we can find stuff
    auto section = sectionIn;
    if (!section.empty() && section.back() != '.'){section.append(".");}

    HasherOptions result;

    // Parse the initialization file
    boost::property_tree::ptree propertyTree;
    boost::property_tree::ini_parser::read_ini(iniFile, propertyTree);

    auto opsLimit = propertyTree.get<std::string> (section + "operationsLimit",
                                                   "interactive"); 
    std::transform(opsLimit.begin(), opsLimit.end(),
                   opsLimit.begin(), ::tolower);
    if (opsLimit == "interactive")
    {
        result.setOperationsLimit(HasherOptions::OperationsLimit::Interactive);
    }
    else if (opsLimit == "moderate")
    {
        result.setOperationsLimit(HasherOptions::OperationsLimit::Moderate);
    }
    else if (opsLimit == "sensitive")
    {
        result.setOperationsLimit(HasherOptions::OperationsLimit::Sensitive);
    }
    else
    {
        throw std::invalid_argument("Operations limit " + opsLimit
                            + "; must be interactive, moderate, or sensitive");
    }

    constexpr size_t toBytes{1024L*1024L};
    const auto memoryLimitMB
        = propertyTree.get<uint32_t>
          (section + "memoryLimitInMB",
          static_cast<uint32_t>
          (result.getMemoryLimitInBytes()/toBytes));
    result.setMemoryLimitInBytes(static_cast<size_t> (memoryLimitMB)*toBytes);

    return result;
}

