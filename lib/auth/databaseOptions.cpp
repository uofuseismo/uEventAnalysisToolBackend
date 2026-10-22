#include <memory>
#include <stdexcept>
#include <utility>
#include "uEventAnalysisToolBackend/auth/databaseOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/database/credentials.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class DatabaseOptions::DatabaseOptionsImpl
{
public:
    UEventAnalysisToolBackend::Database::Credentials mCredentials; 
    Password::HasherOptions mPasswordHasherOptions;
    bool mHasCredentials{false};
};

/// Constructor
DatabaseOptions::DatabaseOptions() :
    pImpl(std::make_unique<DatabaseOptionsImpl> ())
{
}

/// Copy constructor
DatabaseOptions::DatabaseOptions(const DatabaseOptions &options)
{
    *this = options;
}

/// Move constructor
DatabaseOptions::DatabaseOptions(DatabaseOptions &&options) noexcept
{
    *this = std::move(options);
}

/// Copy assignment
DatabaseOptions& DatabaseOptions::operator=(const DatabaseOptions &options)
{
    if (&options == this){return *this;}
    pImpl = std::make_unique<DatabaseOptionsImpl> (*options.pImpl);
    return *this;
}

/// Move assignment
DatabaseOptions& DatabaseOptions::operator=(DatabaseOptions &&options) noexcept
{
    if (&options == this){return *this;}
    pImpl = std::move(options.pImpl);
    return *this;
}

/// Destructor
DatabaseOptions::~DatabaseOptions() = default;

/// Creds
void DatabaseOptions::setCredentials(
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
    pImpl->mCredentials = credentials;
    pImpl->mHasCredentials = true;
}

UEventAnalysisToolBackend::Database::Credentials
DatabaseOptions::getCredentials() const
{
    if (!hasCredentials())
    {
        throw std::runtime_error("Credentials not set");
    }
    return pImpl->mCredentials;
}

bool DatabaseOptions::hasCredentials() const noexcept
{
    return pImpl->mHasCredentials;
}

/// Password hasher options
void DatabaseOptions::setPasswordHasherOptions(
    const Password::HasherOptions &options)
{
    pImpl->mPasswordHasherOptions = options;
}

Password::HasherOptions 
DatabaseOptions::getPasswordHasherOptions() const noexcept
{
    return pImpl->mPasswordHasherOptions;
}
