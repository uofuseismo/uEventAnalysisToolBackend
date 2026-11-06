#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LIST_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LIST_HPP
#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace UEventAnalysisToolBackend::Auth
{
/// @class SchemaPermission
/// @brief Defines the user's permission in a schema.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license. 
class SchemaPermission
{
public:
    enum class Permission
    {   
        ReadOnly,  /*!< The user can only perform read actions in this schema. */
        ReadWrite  /*!< The user can perform read and write actions in this schema. */
    };  
public:
    /// @brief Constructor.
    SchemaPermission();
    /// @brief Copy constructor.
    SchemaPermission(const SchemaPermission &schemaPermission);
    /// @brief Move constructor.
    SchemaPermission(SchemaPermission &&schemaPermsission) noexcept;

    /// @brief Sets the schema name.
    void setSchema(const std::string &schema);
    /// @result The schema.
    /// @throws std::runtime_error if \c hasSchema() is false.
    [[nodiscard]] std::string getSchema() const;
    /// @result True indicates that the schema was set.
    [[nodiscard]] bool hasSchema() const noexcept;

    /// @brief Sets the user's permission in the schema.
    void setPermission(const Permission permission) noexcept;
    /// @result The user's permission in this schema permission.
    [[nodiscard]] Permission getPermission() const;
    /// @result True indicates that the permissions level was set.
    [[nodiscard]] bool hasPermission() const noexcept;

    /// @brief Sets when permission was granted to this schema.
    void setWhenGranted(const std::chrono::microseconds &timestamp) noexcept;
    /// @result When this user was granted permission to this schema.
    /// @throws std::runtime_error if \hasWhenGranted()
    [[nodiscard]] std::chrono::microseconds getWhenGranted() const;    
    /// @result True indicates that the time when granted was set.
    [[nodiscard]] bool hasWhenGranted() const noexcept;

    /// @brief Converts this class to a message.
    /// @note This is defined for UEventAnalysisToolAPI::Admin::V1::ListUsersResponse::SchemaPermission.
    template<typename U> [[nodiscard]] U toMessage() const;

    /// @brief Copy assignment.
    SchemaPermission& operator=(const SchemaPermission &schemaPermission);
    /// @brief Move assignment.
    SchemaPermission& operator=(SchemaPermission &&schemaPermission) noexcept;
    /// @brief Destructor.
    ~SchemaPermission();
private:
    class SchemaPermissionImpl;
    std::unique_ptr<SchemaPermissionImpl> pImpl;
};

/// @class ActiveKey
/// @brief Defines an active key.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license. 
class ActiveKey
{
public:
    /// @brief The key algorithm.
    enum class Algorithm
    {
        ed25519  /*!< Key is made with the ed25519 algorithm. */
    };
public:
    /// @brief Constructor.
    ActiveKey();
    /// @brief Copy constructor.
    ActiveKey(const ActiveKey &key);
    /// @brief Move constructor.
    ActiveKey(ActiveKey &&key) noexcept;

    /// @brief Sets the key's name - e.g., maggies-laptop.
    void setName(const std::string &name);
    /// @result The key name.
    /// @throws std::runtime_error if \c hasName() is false.
    [[nodiscard]] std::string getName() const;
    /// @result True indicates the key name was est.
    [[nodiscard]] bool hasName() const noexcept;

    /// @brief Sets the key algorithm.
    void setAlgorithm(Algorithm algorithm) noexcept;
    /// @result The key algorithm.
    /// @throws std::runtime_error if \c hasAlgorithm() is false.
    [[nodiscard]] Algorithm getAlgorithm() const;
    /// @result True indicates the algorithm was set.
    [[nodiscard]] bool hasAlgorithm() const noexcept;

    /// @brief The sha256 fingerprint of the public key, e.g.,
    ///        SHA256:3q2+7w...
    /// @note This should be enough to distinguish keys.
    void setFingerprint(const std::string &fingerprint);
    /// @result The sha256 hash of the user's public key.
    [[nodiscard]] std::string getFingerprint() const;
    /// @result True indicates that the fingerprint was set.
    [[nodiscard]] bool hasFingerprint() const noexcept;

    /// @brief The time when the key was registered.
    void setWhenRegistered(const std::chrono::microseconds &timestamp);
    /// @result The time when the key was registered.
    /// @throws std::runtime_error if \c hasWhenRegistered() is false.
    [[nodiscard]] std::chrono::microseconds getWhenRegistered() const;
    /// @result True indicates that the registration time was set.
    [[nodiscard]] bool hasWhenRegistered() const noexcept;

    /// @brief The time when the key expires.
    void setExpiration(const std::chrono::microseconds &timestamp);
    /// @result The time when the key expires.
    [[nodiscard]] std::optional<std::chrono::microseconds> getExpiration() const noexcept;

    /// @brief The time when the key was last used.
    void setLastUsed(const std::chrono::microseconds &timestamp);
    /// @result The time when the key was last used.
    [[nodiscard]] std::optional<std::chrono::microseconds> getLastUsed() const noexcept;

    /// @brief Copy assignment.
    ActiveKey& operator=(const ActiveKey &key);
    /// @brief Move assignment.
    ActiveKey& operator=(ActiveKey &&key) noexcept;
    /// @brief Destructor.
    ~ActiveKey();
private:
    class ActiveKeyImpl;
    std::unique_ptr<ActiveKeyImpl> pImpl;
};

/// @class InactiveKey
/// @brief Defines an inactive key - either expired or revoked.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license. 
class InactiveKey
{   
public:
    /// @brief The key algorithm.
    enum class Algorithm
    {
        ed25519  /*!< Key is made with the ed25519 algorithm. */
    };
    /// @brief Reason the key is not active.
    enum class Reason
    {
        Revoked, /*!< The key is revoked. */
        Expired  /*!< The key is invalid because it has been expired. */
    };
public:
    /// @brief Constructor.
    InactiveKey();
    /// @brief Copy constructor.
    InactiveKey(const InactiveKey &key);
    /// @brief Move constructor.
    InactiveKey(InactiveKey &&key) noexcept;

    /// @brief Sets the key's name - e.g., maggies-old-laptop.
    void setName(const std::string &name);
    /// @result The key name.
    /// @throws std::runtime_error if \c hasName() is false.
    [[nodiscard]] std::string getName() const;
    /// @result True indicates the key name was est.
    [[nodiscard]] bool hasName() const noexcept;

    /// @brief Sets the key algorithm.
    void setAlgorithm(Algorithm algorithm) noexcept;
    /// @result The key algorithm.
    /// @throws std::runtime_error if \c hasAlgorithm() is false.
    [[nodiscard]] Algorithm getAlgorithm() const;
    /// @result True indicates the algorithm was set.
    [[nodiscard]] bool hasAlgorithm() const noexcept;

    /// @brief The sha256 fingerprint of the public key, e.g.,
    ///        SHA256:3q2+7w...
    /// @note This should be enough to distinguish keys.
    void setFingerprint(const std::string &fingerprint);
    /// @result The sha256 hash of the user's public key.
    [[nodiscard]] std::string getFingerprint() const;
    /// @result True indicates that the fingerprint was set.
    [[nodiscard]] bool hasFingerprint() const noexcept;

    /// @brief Set reason.
    void setReason(Reason reason) noexcept;
    /// @result The reason the key is inactive.
    [[nodiscard]] Reason getReason() const;
    /// @result True indicates the reason.
    [[nodiscard]] bool hasReason() const noexcept;

    /// @brief The time when the key was registered.
    void setWhenRegistered(const std::chrono::microseconds &timestamp);
    /// @result The time when the key was registered.
    /// @throws std::runtime_error if \c hasWhenRegistered() is false.
    [[nodiscard]] std::chrono::microseconds getWhenRegistered() const;
    /// @result True indicates that the registration time was set.
    [[nodiscard]] bool hasWhenRegistered() const noexcept;
    
    /// @brief The time when the was invalidated - either deactivated
    ///        or revoked.
    void setWhenInvalidated(const std::chrono::microseconds &timestamp);
    /// @result The time when the key was invalidated.
    /// @throws std::runtime_error if \c hasWhenInvalidated() is false.
    [[nodiscard]] std::chrono::microseconds getWhenInvalidated() const;
    /// @result True indicates the invalidation time was set.
    [[nodiscard]] bool hasWhenInvalidated() const noexcept;
    
    /// @brief The time when the key was last used.
    void setLastUsed(const std::chrono::microseconds &timestamp);
    /// @result The time when the key was last used.
    [[nodiscard]] std::optional<std::chrono::microseconds> getLastUsed() const noexcept;

    /// @brief Copy assignment.
    InactiveKey& operator=(const InactiveKey &key);
    /// @brief Move assignment.
    InactiveKey& operator=(InactiveKey &&key) noexcept;
    /// @brief Destructor.
    ~InactiveKey();
private:
    class InactiveKeyImpl;
    std::unique_ptr<InactiveKeyImpl> pImpl;
};

/// @class ActiveUser
/// @brief Defines an active user.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license. 
class ActiveUser
{
public:
    /// @brief Constructor.
    ActiveUser();
    /// @brief Copy constructor.
    ActiveUser(const ActiveUser &user);
    /// @brief Move constructor.
    ActiveUser(ActiveUser &&user) noexcept;

    /// @brief Sets the user's name - e.g., sal.
    void setName(const std::string &name);
    /// @result The user's name.
    /// @throws std::runtime_error if \c hasName() is false.
    [[nodiscard]] std::string getName() const;
    /// @result True indicates the user's name was est.
    [[nodiscard]] bool hasName() const noexcept;

    /// @brief Indicate this user is an administrator.
    void setIsAdministrator() noexcept;
    /// @brief Indicate this user is not an administrator.
    void setIsNotAdministrator() noexcept;
    /// @result True indicates this is an administrative user.
    /// @throws std::runtime_error if \c wasIsAdministratorSet() is false.
    [[nodiscard]] bool isAdministrator() const;
    /// @result True indicates \c setIsAdministrator() or
    ///         \c setIsNotAdministrator() was called.
    [[nodiscard]] bool wasIsAdministratorSet() const noexcept;

    /// @brief The time when the accounts was created.
    void setWhenCreated(const std::chrono::microseconds &timestamp);
    /// @result The time when the account was created.
    /// @throws std::runtime_error if \c hasWhenCreated() is false.
    [[nodiscard]] std::chrono::microseconds getWhenCreated() const;
    /// @result True indicates that account creation time was set.
    [[nodiscard]] bool hasWhenCreated() const noexcept;

    /// @brief The time when the user last logged in by password or key.
    void setLastLogin(const std::chrono::microseconds &timestamp);
    /// @result The time when the user last logged in.
    /// @note We do not count replacing an issued password as a login.
    [[nodiscard]] std::optional<std::chrono::microseconds> getLastLogin() const noexcept;

    /// @brief Sets the schema permissions.
    void setSchemaPermissions(std::vector<SchemaPermission> &&permissions);
    /// @result The schema permissions.
    [[nodiscard]] std::vector<SchemaPermission> getSchemaPermissions() const noexcept;

    /// @brief Sets the active keys.
    void setActiveKeys(std::vector<ActiveKey> &&activeKeys);
    /// @result The active keys.
    [[nodiscard]] std::vector<ActiveKey> getActiveKeys() const noexcept;

    /// @brief Sets the inactive keys.
    void setInactiveKeys(std::vector<InactiveKey> &&inactiveKeys); 
    /// @result The inactive keys.
    [[nodiscard]] std::vector<InactiveKey> getInactiveKeys() const noexcept;

    /// @brief Copy assignment.
    ActiveUser& operator=(const ActiveUser &user);
    /// @brief Move assignment.
    ActiveUser& operator=(ActiveUser &&user) noexcept;
    /// @brief Destructor.
    ~ActiveUser();
private:
    class ActiveUserImpl;
    std::unique_ptr<ActiveUserImpl> pImpl;
};

/// @class ProvisionalUser
/// @brief Defines a provisional user.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license. 
class ProvisionalUser
{
public:
    /// @brief Constructor.
    ProvisionalUser();
    /// @brief Copy constructor.
    ProvisionalUser(const ProvisionalUser &user);
    /// @brief Move constructor.
    ProvisionalUser(ProvisionalUser &&user) noexcept;

    /// @brief Sets the user's name - e.g., sal.
    void setName(const std::string &name);
    /// @result The user's name.
    /// @throws std::runtime_error if \c hasName() is false.
    [[nodiscard]] std::string getName() const;
    /// @result True indicates the user's name was est.
    [[nodiscard]] bool hasName() const noexcept;

    /// @brief The time when the issued password stops working.
    void setExpiration(const std::chrono::microseconds &timestamp);
    /// @result The time when the issued password stops working.
    /// @throws std::runtime_error if \c hasExpiration() is false.
    [[nodiscard]] std::chrono::microseconds getExpiration() const;
    /// @result True indicates the password expiration was set.
    [[nodiscard]] bool hasExpiration() const noexcept;

    /// @brief The time when the accounts was created.
    void setWhenCreated(const std::chrono::microseconds &timestamp);
    /// @result The time when the account was created.
    /// @throws std::runtime_error if \c hasWhenCreated() is false.
    [[nodiscard]] std::chrono::microseconds getWhenCreated() const;
    /// @result True indicates that account creation time was set.
    [[nodiscard]] bool hasWhenCreated() const noexcept;

    /// @brief Indicate the account expiration has passed and the user
    ///        is locked out until an admin resets their password.
    void setExpired() noexcept;
    /// @brief Indicate the account has not expired and the user can still
    ///        log in with their temporary password.
    void setNotExpired() noexcept;
    /// @result True indicates the account expired.
    /// @throws std::runtime_error \c wasIsExpiredSet() is false.
    [[nodiscard]] bool isExpired() const;
    /// @result True indicates that \c setExpired() or \c setNotExpired() 
    ///         was called.
    [[nodiscard]] bool wasIsExpiredSet() const noexcept;

    /// @brief The time when the user last logged in by password or key.
    void setLastLogin(const std::chrono::microseconds &timestamp);
    /// @result The time when the user last logged in.
    /// @note We do not count replacing an issued password as a login.
    [[nodiscard]] std::optional<std::chrono::microseconds> getLastLogin() const noexcept;

    /// @brief Sets the schema permissions this user will be able to access.
    void setSchemaPermissions(std::vector<SchemaPermission> &&permissions);
    /// @result The schema permissions this will be able to access.
    [[nodiscard]] std::vector<SchemaPermission> getSchemaPermissions() const noexcept;

    /// @brief Sets the inactive keys.
    void setInactiveKeys(std::vector<InactiveKey> &&inactiveKeys);
    /// @result The inactive keys.
    [[nodiscard]] std::vector<InactiveKey> getInactiveKeys() const noexcept;

    /// @brief Copy assignment.
    ProvisionalUser& operator=(const ProvisionalUser &user);
    /// @brief Move assignment.
    ProvisionalUser& operator=(ProvisionalUser &&user) noexcept;
    /// @brief Destructor.
    ~ProvisionalUser();
private:
    class ProvisionalUserImpl;
    std::unique_ptr<ProvisionalUserImpl> pImpl;
};

/// @class UserList
/// @brief The list of active and provisional users.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license. 
class UserList
{
public:
    /// @brief Constructor.
    UserList();
    /// @brief Copy constructor.
    UserList(const UserList &list);
    /// @brief Move constructor.
    UserList(UserList &&list) noexcept;

    /// @brief Sets the actives users.
    void setActiveUsers(std::vector<ActiveUser> &&activeUsers);
    /// @result The active users.
    [[nodiscard]] std::vector<ActiveUser> getActiveUsers() const noexcept;
 
    /// @brief Sets the provisional users.
    void setProvisionalUsers(std::vector<ProvisionalUser> &&provisionalUsers);
    /// @result The provisional users.
    [[nodiscard]] std::vector<ProvisionalUser> getProvisionalUsers() const noexcept;

    /// @brief Copy assignment.
    UserList& operator=(const UserList &list);
    /// @brief Move assignment.
    UserList& operator=(UserList &&list) noexcept;
    /// @brief Destructor.
    ~UserList();
private:
    class UserListImpl;
    std::unique_ptr<UserListImpl> pImpl;
};

}
#endif
