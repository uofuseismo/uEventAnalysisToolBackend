#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include <uEventAnalysisToolAPI/auth/v1/password_requirements_response.pb.h>

using namespace UEventAnalysisToolBackend::Auth::Password;

class PasswordPolicy::PasswordPolicyImpl
{
public:
    int mMinimumLength{12};
    bool mRequiresSpecialCharacter{false};
    bool mRequiresNumber{true};
    bool mNewAndOldPasswordMustBeDifferent{true};
};

/// Constructor
PasswordPolicy::PasswordPolicy() :
    pImpl(std::make_unique<PasswordPolicyImpl> ())
{
}

/// Copy constructor
PasswordPolicy::PasswordPolicy(const PasswordPolicy &policy)
{
    *this = policy;
}

/// Move constructor 
PasswordPolicy::PasswordPolicy(PasswordPolicy &&policy) noexcept
{
    *this = std::move(policy);
}

/// Copy assignment
PasswordPolicy& PasswordPolicy::operator=(const PasswordPolicy &policy)
{
    if (&policy == this){return *this;}
    pImpl = std::make_unique<PasswordPolicyImpl> (*policy.pImpl);
    return *this;
}

/// Move assignment
PasswordPolicy& PasswordPolicy::operator=(PasswordPolicy &&policy) noexcept
{
    if (&policy == this){return *this;}
    pImpl = std::move(policy.pImpl);
    return *this;
}

/// Destructor
PasswordPolicy::~PasswordPolicy() = default;

/// Minimum password length
void PasswordPolicy::setMinimumLength(const int length)
{
    if (length < 1)
    {
        throw std::invalid_argument("Minimum password length must be positive");
    }
    pImpl->mMinimumLength = length;
}

int PasswordPolicy::getMinimumLength() const noexcept
{
    return pImpl->mMinimumLength;
}

/// Number
void PasswordPolicy::enableRequiresNumber() noexcept
{
    pImpl->mRequiresNumber = true;
}
 
void PasswordPolicy::disableRequiresNumber() noexcept
{
    pImpl->mRequiresNumber = false;
}

bool PasswordPolicy::requiresNumber() const noexcept
{
    return pImpl->mRequiresNumber;
}

/// Special character
void PasswordPolicy::enableRequiresSpecialCharacter() noexcept
{
    pImpl->mRequiresSpecialCharacter = true;
}

void PasswordPolicy::disableRequiresSpecialCharacter() noexcept
{
    pImpl->mRequiresSpecialCharacter = false;
}

bool PasswordPolicy::requiresSpecialCharacter() const noexcept
{
    return pImpl->mRequiresSpecialCharacter;
}

/// New/old passwords differ
void PasswordPolicy::enableNewAndOldPasswordMustDiffer() noexcept
{
    pImpl->mNewAndOldPasswordMustBeDifferent = true;
}

void PasswordPolicy::disableNewAndOldPasswordMustDiffer() noexcept
{
    pImpl->mNewAndOldPasswordMustBeDifferent = false;
}

bool PasswordPolicy::newAndOldPasswordMustDiffer() const noexcept
{
    return pImpl->mNewAndOldPasswordMustBeDifferent;
}

/// Conversions
template<>
UEventAnalysisToolAPI::Auth::V1::PasswordRequirementsResponse
PasswordPolicy::toMessage(const std::string &identifier) const noexcept
{
    UEventAnalysisToolAPI::Auth::V1::PasswordRequirementsResponse response;
    response.set_identifier(identifier);
    response.set_minimum_length(getMinimumLength());
    response.set_requires_number(requiresNumber());
    response.set_requires_special_character(requiresSpecialCharacter());
    response.set_new_and_old_password_must_differ(newAndOldPasswordMustDiffer());
    return response;
}

PasswordPolicy PasswordPolicy::fromInitializationFile(
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

    PasswordPolicy result;

    // Parse the initialization file
    boost::property_tree::ptree propertyTree;
    boost::property_tree::ini_parser::read_ini(iniFile, propertyTree);

    const auto minimumLength
        = propertyTree.get<int>
           (section + "minimumLength",
           static_cast<int> (result.getMinimumLength()));
    result.setMinimumLength(minimumLength);

    auto requiresNumber
        = propertyTree.get<bool>
          (section + "requiresNumber",
           result.requiresNumber());
    if (requiresNumber)
    {
        result.enableRequiresNumber();
    }
    else
    {
        result.disableRequiresNumber();
    }

    auto requiresSpecialCharacter
        = propertyTree.get<bool>
          (section + "requiresSpecialCharacter",
          result.requiresSpecialCharacter());
    if (requiresSpecialCharacter)
    {
        result.enableRequiresSpecialCharacter();
    }
    else
    {
        result.disableRequiresSpecialCharacter();
    }

    auto newAndOldPasswordMustBeDifferent
        = propertyTree.get<bool>
          (section + "newAndOldMustBeDifferent",
           result.newAndOldPasswordMustDiffer());
    if (newAndOldPasswordMustBeDifferent)
    {
        result.enableNewAndOldPasswordMustDiffer();
    }
    else
    {
        result.disableNewAndOldPasswordMustDiffer();
    }

    return result;
}
