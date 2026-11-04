#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_ADMINISTRATION_OPTIONS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_ADMINISTRATION_OPTIONS_HPP
#include <chrono>
//#include <filesystem>
#include <memory>
#include <string>
namespace UEventAnalysisToolBackend
{
 namespace Database
 {
  class Credentials;
 }
 namespace Auth::Password
 {
  class HasherOptions;
  class PasswordPolicy;
 }
}
namespace UEventAnalysisToolBackend::Auth
{
/// @class UserAdministrationOptions userAdministrationOptions.hpp
/// @brief Options influencing the administrator management of (some)
///        user properties.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class UserAdministrationOptions
{
public:
    /// @brief Constructor
    UserAdministrationOptions();
    /// @brief Copy constructor.
    UserAdministrationOptions(const UserAdministrationOptions &options);
    /// @brief Move constructor.
    UserAdministrationOptions(UserAdministrationOptions &&options) noexcept;

    /// @brief Sets the credentials for forming a database connection. 
    /// @throws std::invalid_argument if the user, password, or database
    ///         name is not set.
    void setDatabaseCredentials(
        const UEventAnalysisToolBackend::Database::Credentials &credentials);
    /// @result The database connection credentials.
    /// @throws std::runtime_error if \c hasDatabaseCredentials() is false.
    [[nodiscard]] UEventAnalysisToolBackend::Database::Credentials getDatabaseCredentials() const;
    /// @result True indicates that the credentials were set.
    [[nodiscard]] bool hasDatabaseCredentials() const noexcept;

    /// @brief Sets the password hasher options.
    void setPasswordHasherOptions(const Password::HasherOptions &options);
    /// @result The password hasher options.
    [[nodiscard]] Password::HasherOptions getPasswordHasherOptions() const noexcept;

    /// @brief Sets the password policy.
    void setPasswordPolicy(const Password::PasswordPolicy &policy);
    /// @result The password policy.
    [[nodiscard]] Password::PasswordPolicy getPasswordPolicy() const noexcept;

    /// @brief Sets the issued password time-to-live.
    void setIssuedPasswordTimeToLive(const std::chrono::seconds &timeToLive);
    /// @result The issued password time to live.
    /// @note By default this is 1 day.
    [[nodiscard]] std::chrono::seconds getIssuedPasswordTimeToLive() const noexcept;

    /// @result The maximum user name length.
    /// @note This is 64.
    [[nodiscard]] static int getMaximumUserNameLength() noexcept;
/*
    /// @brief Loads the user admin options options from an ini file.
    [[nodiscard]] static UserAdministrationOptions
        fromInitializationFile(const std::filesystem::path &iniFile,
                               const std::string &section);
*/

    /// @brief Destructor.
    ~UserAdministrationOptions();
    /// @brief Copy assignment.
    UserAdministrationOptions& operator=(const UserAdministrationOptions &options);
    /// @brief Move assignment.
    UserAdministrationOptions& operator=(UserAdministrationOptions &&options) noexcept;
private:
    class UserAdministrationOptionsImpl;
    std::unique_ptr<UserAdministrationOptionsImpl> pImpl;
};
}
#endif
