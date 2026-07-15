#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_DATABASE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_DATABASE_HPP
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/authenticator.hpp>

namespace UEventAnalysisToolBackend::Auth
{
 class DatabaseOptions;
}

namespace UEventAnalysisToolBackend::Auth
{
/// @class Database database.hpp
/// @brief Validates the user against the ueatdb database.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class Database : public IAuthenticator
{
public:
    /// @brief Constructor.
    Database(const DatabaseOptions &options,
             std::shared_ptr<spdlog::logger> logger); 
 
    /// @brief Authenticate the user and password.
    [[nodiscard]] IAuthenticator::Result authenticateBasic(const std::pair<std::string, std::string> &userNameAndPassword) override final;

    /// @brief Gets the schemas the user may access and at what level.
    /// @result (schema, permission) pairs - e.g., ("utah", "read_write").
    ///         This is empty if the user has no permissions.
    /// @throws std::invalid_argument if the user is empty.
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> getPermissions(const std::string &user) const;

    /// @brief Adds a user with the given password.  The password is hashed
    ///        before it goes to the database.
    /// @result True on success; false if the user already exists.
    /// @throws std::invalid_argument if the user or password is empty.
    [[nodiscard]] bool addUser(const std::pair<std::string, std::string> &userNameAndPassword);
    /// @brief Updates the user's password.
    /// @result True on success; false if the user does not exist.
    /// @throws std::invalid_argument if the user or password is empty.
    [[nodiscard]] bool updatePassword(const std::pair<std::string, std::string> &userNameAndPassword);
    /// @brief Removes a user; their permissions cascade away with them.
    /// @result True if the user was removed; false if no such user.
    /// @throws std::invalid_argument if the user is empty.
    [[nodiscard]] bool removeUser(const std::string &user);

    /// @brief Registers a public key for programmatic access by the user -
    ///        a la SSH authorized_keys.
    /// @param[in] user       The user name.
    /// @param[in] keyName    The user-facing key label - e.g., "laptop".
    /// @param[in] publicKey  The base64-encoded ed25519 public key.
    /// @result True on success; false if the user does not exist, the key
    ///         name is taken for this user, or the public key is already
    ///         registered.
    /// @throws std::invalid_argument if any input is empty.
    [[nodiscard]] bool addUserKey(const std::string &user,
                                  const std::string &keyName,
                                  const std::string &publicKey);
    /// @brief Revokes (never deletes - the row is the audit trail) the
    ///        user's named key.
    /// @result True if an active key was revoked.
    /// @throws std::invalid_argument if the user or key name is empty.
    [[nodiscard]] bool revokeUserKey(const std::string &user,
                                     const std::string &keyName);
    /// @brief Authenticates a request signed with a registered key.
    /// @param[in] message    The bytes the client signed.
    /// @param[in] signature  The base64-encoded 64-byte ed25519 detached
    ///                       signature of the message.
    /// @param[in] publicKey  The base64-encoded 32-byte ed25519 public key.
    /// @result Authenticated if the key is registered, active, and the
    ///         signature verifies.
    /// @throws std::invalid_argument if any input is empty.
    [[nodiscard]] IAuthenticator::Result authenticateKey(
        const std::string &message,
        const std::string &signature,
        const std::string &publicKey);

    /// @brief Destructor.
    ~Database();

    Database() = delete;
    Database(const Database &) = delete;
    Database(Database &&) noexcept = delete;
    Database& operator=(const Database &) = delete;
    Database& operator=(Database &&) noexcept = delete;
private:
    class DatabaseImpl;
    std::unique_ptr<DatabaseImpl> pImpl;
};
}
#endif
