#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <sodium/core.h>
#include <sodium/randombytes.h>
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include <uEventAnalysisToolAPI/auth/v1/password_requirements.pb.h>

using namespace UEventAnalysisToolBackend::Auth::Password;

namespace
{
// Avoid 1's and I's end l's and 0's and O's because that's confusing because that's confusing.  

constexpr std::string_view ALPHABET{
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"};
constexpr std::string_view NUMBERS{
    "23456789"};
constexpr std::string_view SPECIAL {
    "*@#[]$!"};

}

class PasswordPolicy::PasswordPolicyImpl
{
public:
    std::pair<int, int> mMinimumAndMaximumLength{12, 64};
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
void PasswordPolicy::setMinimumAndMaximumLength(const std::pair<int, int> &minAndMax)
{
    if (minAndMax.first < 1)
    {
        throw std::invalid_argument("Minimum password length must be positive");
    }
    if (minAndMax.second <= minAndMax.first)
    {
        throw std::invalid_argument("Maximum length must exceed minimum length");
    }
    pImpl->mMinimumAndMaximumLength = minAndMax;
}

std::pair<int, int> PasswordPolicy::getMinimumAndMaximumLength() const noexcept
{
    return pImpl->mMinimumAndMaximumLength;
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

/// Creates a temporary password based on the current policy.
std::string PasswordPolicy::createTemporaryPassword() const
{
    auto [candidateMinimumLength, candidateMaximumLength]
         = getMinimumAndMaximumLength();
    int passwordLength{candidateMinimumLength};
    if (requiresNumber())
    {
        if (passwordLength + 1 <= candidateMaximumLength)
        {
            passwordLength = passwordLength + 1;
        }
    }
    if (requiresSpecialCharacter())
    {
        if (passwordLength + 1 <= candidateMaximumLength)
        {
            passwordLength = passwordLength + 1;
        }
    }
    // Initialize our RNG
    if (sodium_init() ==-1)
    {
        throw std::runtime_error("Failed to initialize sodium");
    }
    std::random_device device;
    std::mt19937 generator(device());
    // First generate a list of random characters
    std::string password;
    std::vector<int> isChangeableIndex(passwordLength);
    for (int i = 0; i < passwordLength; ++i)
    {
        password.push_back(::ALPHABET[randombytes_uniform(
            static_cast<std::uint32_t> (::ALPHABET.size()))]);
        isChangeableIndex[i] = i;
    }
    // Designate one survivor
    std::vector<int> survivorIndex;
    survivorIndex.reserve(1);
    std::ranges::sample(isChangeableIndex,
                        std::back_inserter(survivorIndex),
                        1,
                        generator); 
    std::erase(isChangeableIndex, survivorIndex.at(0));
    // This password has to survive for like 2 days.  Let's not go crazy.
    int nChange{1};
    if (requiresNumber())
    {
        if (isChangeableIndex.size() > 1)
        {
            std::vector<int> samples;
            samples.reserve(nChange);
            std::ranges::sample(isChangeableIndex,
                                std::back_inserter(samples),
                                nChange,
                                generator); 
            for (auto s : samples)
            {
                auto number = ::NUMBERS[randombytes_uniform(
                   static_cast<std::uint32_t> (::NUMBERS.size()))];
                password[s] = number;
            } 
            for (auto s : samples)
            {
                std::erase(isChangeableIndex, s); 
            }
        }
    }
    nChange = 1;
    if (requiresSpecialCharacter())
    {
        if (isChangeableIndex.size() > 1)
        {
            std::vector<int> samples;
            samples.reserve(nChange);
            std::ranges::sample(isChangeableIndex,
                                std::back_inserter(samples),
                                nChange,
                                generator); 
            for (auto s : samples)
            {
                auto specialChar = ::SPECIAL[randombytes_uniform(
                   static_cast<std::uint32_t> (::SPECIAL.size()))];
                password[s] = specialChar;
            }
            for (auto s : samples)
            {
                std::erase(isChangeableIndex, s);
            }
        }
    }
    return password;
}

/// Conversions
template<>
UEventAnalysisToolAPI::Auth::V1::PasswordRequirements
PasswordPolicy::toMessage() const noexcept
{
    UEventAnalysisToolAPI::Auth::V1::PasswordRequirements response;
    auto [minLength, maxLength] = getMinimumAndMaximumLength();
    response.set_minimum_length(minLength);
    response.set_maximum_length(maxLength);
    response.set_requires_number(requiresNumber());
    response.set_requires_special_character(requiresSpecialCharacter());
    response.set_new_and_old_password_must_differ(newAndOldPasswordMustDiffer());
    return response;
}

/// Validate
PasswordPolicy::ValidationResult
PasswordPolicy::validate(
    const std::pair<std::string, std::string> &newAndOldPassword) const noexcept
{
    if (newAndOldPasswordMustDiffer() &&
        newAndOldPassword.first == newAndOldPassword.second)
    {
        return ValidationResult::PasswordsMatch;
    }
    auto password = newAndOldPassword.first;
    auto length = static_cast<int> (password.length());
    auto [minLength, maxLength] = getMinimumAndMaximumLength();
    if (length < minLength)
    {
        return ValidationResult::TooShort;
    }
    if (length > maxLength)
    {
        return ValidationResult::TooLong;
    }
    if (requiresNumber())
    {
        const bool hasDigit
            = std::ranges::any_of(password,
                                  [](const char c)
                                  {
                                      return c >= '0' && c <= '9';
                                  });
        if (!hasDigit){return ValidationResult::NoNumber;}
    }
    if (requiresSpecialCharacter())
    {
        constexpr std::string_view specialCharacters
            {R"(!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)"};
        const bool hasSpecial
            = std::ranges::any_of(password,
                                  [&](const char c)
                                  {
                                       return specialCharacters.contains(c);
                                  });
        if (!hasSpecial)
        {
            return ValidationResult::NoSpecialCharacter;
        }
    }
    return ValidationResult::Valid;
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

    auto [minLength, maxLength] = result.getMinimumAndMaximumLength();

    minLength = propertyTree.get<int> (section + "minimumLength", minLength);
    maxLength = propertyTree.get<int> (section + "maximumLength", maxLength);
    result.setMinimumAndMaximumLength(std::pair {minLength, maxLength});

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

    auto newAndOldPasswordMustDiffer
        = propertyTree.get<bool>
          (section + "newAndOldPasswordMustDiffer",
           result.newAndOldPasswordMustDiffer());
    if (newAndOldPasswordMustDiffer)
    {
        result.enableNewAndOldPasswordMustDiffer();
    }
    else
    {
        result.disableNewAndOldPasswordMustDiffer();
    }

    return result;
}
