#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_DATABASE_OPTIONS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_DATABASE_OPTIONS_HPP
#include <memory>

namespace UEventAnalysisToolBackend::Database
{
 class Credentials;
}
namespace UEventAnalysisToolBackend::Auth::Password
{
 class HasherOptions;
}



namespace UEventAnalysisToolBackend::Auth
{
/// @class DatabaseOptions databaseOptions.hpp
/// @brief Defines the options for the database authenticator.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class DatabaseOptions
{
public:

    /// @brief Constructor.
    DatabaseOptions();
    /// @brief Copy constructor.
    DatabaseOptions(const DatabaseOptions &options);
    /// @brief Move constructor.
    DatabaseOptions(DatabaseOptions &&options) noexcept;

    /// @brief Sets the password hasher options.
    void setPasswordHasherOptions(const Password::HasherOptions &options);
    /// @result The password hasher options.
    [[nodiscard]] Password::HasherOptions getPasswordHasherOptions() const noexcept;

    /// @brief Sets the credentials for the database with the users table.
    void setCredentials(const UEventAnalysisToolBackend::Database::Credentials &credentials);
    /// @result The database credentials.
    /// @throws std::runtime_error if \c hasCredentials() is false.
    [[nodiscard]] UEventAnalysisToolBackend::Database::Credentials getCredentials() const;
    /// @result True indicates the credentials were set.
    [[nodiscard]] bool hasCredentials() const noexcept;
 
    /// @brief Destructor.
    ~DatabaseOptions();
    /// @brief Copy assignment.
    DatabaseOptions& operator=(const DatabaseOptions &options);
    /// @brief Move assignment.
    DatabaseOptions& operator=(DatabaseOptions &&options) noexcept;
public:
    class DatabaseOptionsImpl;
    std::unique_ptr<DatabaseOptionsImpl> pImpl; 
};
}
#endif
