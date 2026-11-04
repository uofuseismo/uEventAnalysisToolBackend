#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_ADMINISTRATION_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_ADMINISTRATION_HPP
#include <expected>
#include <memory>
#include <string>
#include <spdlog/logger.h>
namespace UEventAnalysisToolBackend::Auth
{
 class UserAdministrationOptions;
}
namespace UEventAnalysisToolBackend::Auth
{
/// @class UserAdministration userAdministration.hpp
/// @brief Allows the administrator to adjust user properties.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class UserAdministration
{
public:
    struct IssuedPassword
    {
        std::string user;           // Stored user name (lower-case)
        std::string issuedPassword; // Plain text, issued once
    };

    enum class Permission
    {
        ReadOnly,  /*!< The user can only perform read actions in this schema. */
        ReadWrite  /*!< The user can perform read and write actions in this schema. */
    };

    enum class ReturnCode
    {
        Success,           /*!< The action was successful. */
        InvalidArgument,   /*!< Empty name, bad schema/permission etc. */
        NoUserFound,       /*!< The user could not be found. */
        NoSchema,          /*!< The schema does not exist. */
        AlreadyExists,     /*!< Creation collision. */
        NotAuthorized,     /*!< The actor is not an administrator. */
        LastAdministrator, /*!< This would leave no administrators. */
        ServerError        /*!< Server error detected. */
    };

public:
    /// @brief Constructor.
    /// @param[in] options  Options for user administration such as database
    ///                     credentials, password policies, password hashing
    ///                     policies etc.
    /// @param[in] logger   The application logger. 
    /// @throws std::invalid_argument if options does not have database
    ///         credentials.
    UserAdministration(const UserAdministrationOptions &options,
                       std::shared_ptr<spdlog::logger> logger);
    /// @result True indicates the class is initialized.
    [[nodiscard]] bool isInitialized() const noexcept;

    /// @brief Creates a provisional user with a temporary password.
    [[nodiscard]] std::expected<IssuedPassword, ReturnCode> createProvisionalUser(const std::string &actor, const std::string &user);

    /// @brief Removes a user.
    [[nodiscard]] ReturnCode removeUser(const std::string &actor, const std::string &user);

    /// @brief Resets a user's password.
    [[nodiscard]] std::expected<IssuedPassword, ReturnCode> resetPassword(const std::string &actor, const std::string &user, bool removeKeys);

    /// @brief Sets a permission to a schema.
    /// @note This is like adding a user to a schema.
    [[nodiscard]] ReturnCode setPermission(const std::string &actor, const std::string &user, const std::string &schema, Permission permission);

    /// @brief Revokes a user's permissions to a schema.
    /// @note This is like removing a user from a schema.
    [[nodiscard]] ReturnCode revokePermission(const std::string &actor, const std::string &user, const std::string &schema);

    /// @brief Sets a user as administrator.
    [[nodiscard]] ReturnCode setAdministrator(const std::string &actor, const std::string &name);

    /// @brief Removes an administrator's privileges.
    [[nodiscard]] ReturnCode revokeAdministrator(const std::string &actor, const std::string &name);

    ~UserAdministration();

    UserAdministration() = delete;
    UserAdministration(const UserAdministration &) = delete;
    UserAdministration(UserAdministration &&) noexcept = delete;
    UserAdministration& operator=(const UserAdministration &) = delete;
    UserAdministration& operator=(UserAdministration &&) noexcept = delete;
private:
    class UserAdministrationImpl;
    std::unique_ptr<UserAdministrationImpl> pImpl;
};
}
#endif
