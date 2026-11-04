#include <chrono>
#include <memory>
#include <stdexcept>
#include <utility>
#include "uEventAnalysisToolBackend/auth/userAdministrationOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolBackend/database/credentials.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class UserAdministrationOptions::UserAdministrationOptionsImpl
{
public:
    UEventAnalysisToolBackend::Database::Credentials mDatabaseCredentials;
    Password::HasherOptions mPasswordHasherOptions;
    Password::PasswordPolicy mPasswordPolicy;
    std::chrono::seconds mIssuedPasswordTTL{std::chrono::days {1}};
    bool mHasDatabaseCredentials{false};
};

/// Constructor
UserAdministrationOptions::UserAdministrationOptions() :
    pImpl(std::make_unique<UserAdministrationOptionsImpl> ())
{
}

/// Copy constructor
UserAdministrationOptions::UserAdministrationOptions(
    const UserAdministrationOptions &options)
{
    *this = options;
}

// /Move constructor
UserAdministrationOptions::UserAdministrationOptions(
    UserAdministrationOptions &&options) noexcept
{
    *this = std::move(options);
}

/// Copy assignment
UserAdministrationOptions& 
UserAdministrationOptions::operator=(const UserAdministrationOptions &options)
{
    if (&options == this){return *this;}
    pImpl = std::make_unique<UserAdministrationOptionsImpl> (*options.pImpl);
    return *this;
}

/// Move assignment
UserAdministrationOptions& 
UserAdministrationOptions::operator=(
    UserAdministrationOptions &&options) noexcept
{
    if (&options == this){return *this;}
    pImpl = std::move(options.pImpl);
    return *this;
}

/// Destructor
UserAdministrationOptions::~UserAdministrationOptions() = default;

/// Time-to-live
void UserAdministrationOptions::setIssuedPasswordTimeToLive(
    const std::chrono::seconds &timeToLive)
{
    if (timeToLive <= std::chrono::seconds {0})
    {   
        throw std::invalid_argument(
           "Issued password time-to-live must be positive");
    }   
    pImpl->mIssuedPasswordTTL = timeToLive;
}

std::chrono::seconds 
UserAdministrationOptions::getIssuedPasswordTimeToLive() const noexcept
{
    return pImpl->mIssuedPasswordTTL;
}

/// Password hasher options
void UserAdministrationOptions::setPasswordHasherOptions(
    const Password::HasherOptions &options)
{
    pImpl->mPasswordHasherOptions = options;
}

Password::HasherOptions
UserAdministrationOptions::getPasswordHasherOptions() const noexcept
{
    return pImpl->mPasswordHasherOptions;
}

/// Password policy
void UserAdministrationOptions::setPasswordPolicy(
    const Password::PasswordPolicy &policy)
{
    pImpl->mPasswordPolicy = policy;
}

Password::PasswordPolicy
UserAdministrationOptions::getPasswordPolicy() const noexcept
{
    return pImpl->mPasswordPolicy;
}


/// Creds
void UserAdministrationOptions::setDatabaseCredentials(
    const UEventAnalysisToolBackend::Database::Credentials &credentials)
{
    if (!credentials.hasUser())
    {   
        throw std::invalid_argument("User not set");
    }   
    if (!credentials.hasPassword())
    {   
        throw std::invalid_argument("Password not set");
    }   
    if (!credentials.hasDatabaseName())
    {   
        throw std::invalid_argument("Database name not set");
    }   
    pImpl->mDatabaseCredentials = credentials;
    pImpl->mHasDatabaseCredentials = true;
}

UEventAnalysisToolBackend::Database::Credentials 
UserAdministrationOptions::getDatabaseCredentials() const
{
    if (!hasDatabaseCredentials())
    {   
        throw std::runtime_error("Credentials not set");
    }   
    return pImpl->mDatabaseCredentials;
}

bool UserAdministrationOptions::hasDatabaseCredentials() const noexcept
{
    return pImpl->mHasDatabaseCredentials;
}

/// Max user name length
int UserAdministrationOptions::getMaximumUserNameLength() noexcept
{
    constexpr int maxLength{64};
    return maxLength;
}
