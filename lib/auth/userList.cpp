#include <chrono>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <google/protobuf/util/time_util.h>
#include "uEventAnalysisToolBackend/auth/userList.hpp"
#include <uEventAnalysisToolAPI/admin/v1/list_users_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/permission.pb.h>

using namespace UEventAnalysisToolBackend::Auth;
namespace UEATAPIV1 = UEventAnalysisToolAPI::Admin::V1;

namespace
{

void checkSchemaPermission(const SchemaPermission &permission)
{
    if (!permission.hasSchema())
    {
        throw std::invalid_argument("Schema not set");
    }
    if (!permission.hasPermission())
    {
        throw std::invalid_argument("Permission not set");
    }
    if (!permission.hasWhenGranted())
    {
        throw std::invalid_argument("Grant time not set");
    }
}

void checkActiveKey(const ActiveKey &key)
{
    if (!key.hasName())
    {
        throw std::invalid_argument("Key name not set");
    }
    if (!key.hasAlgorithm())
    {
        throw std::invalid_argument("Algorithm name not set");
    }
    if (!key.hasFingerprint())
    {
        throw std::invalid_argument("Fingerprint not set");
    }
    if (!key.hasWhenRegistered())
    {
        throw std::invalid_argument("Registration time not set");
    }
}

void checkInactiveKey(const InactiveKey &key)
{
    if (!key.hasName())
    {
        throw std::invalid_argument("Key name not set");
    }
    if (!key.hasAlgorithm())
    {
        throw std::invalid_argument("Algorithm name not set");
    }
    if (!key.hasReason())
    {
        throw std::invalid_argument("Reason not set");
    }
    if (!key.hasFingerprint())
    {
        throw std::invalid_argument("Fingerprint not set");
    }
    if (!key.hasWhenRegistered())
    {
        throw std::invalid_argument("Registration time not set");
    }
    if (!key.hasWhenInvalidated())
    {
        throw std::invalid_argument("Invalidation time not set");
    }
}

void checkActiveUser(const ActiveUser &user)
{
    if (!user.hasName()){throw std::invalid_argument("User name not set");}
    if (!user.wasIsAdministratorSet())
    {
        throw std::invalid_argument("User admin status not set");
    }
    if (!user.hasWhenCreated())
    {
        throw std::invalid_argument("User creation time not set");
    }
    if (!user.hasWhenPasswordUpdated())
    {
        throw std::invalid_argument("Password update time not set");
    }
}

void checkProvisionalUser(const ProvisionalUser &user)
{
    if (!user.hasName()){throw std::invalid_argument("User name not set");}
    if (!user.wasIsAdministratorSet())
    {
        throw std::invalid_argument("User admin status not set");
    } 
    if (!user.hasWhenCreated())
    { 
        throw std::invalid_argument("User creation time not set");
    }
    if (!user.hasExpiration())
    { 
        throw std::invalid_argument("Expiration not set");
    } 
    if (!user.wasIsExpiredSet())
    {
        throw std::invalid_argument("Expired status not set");
    }
    if (!user.wasPasswordResetSet())
    {
        throw std::invalid_argument("Password reset status not set");
    } 
}

}

///-------------------------------Schema Permission--------------------------///
 
class SchemaPermission::SchemaPermissionImpl
{
public:
    std::string mSchema;
    std::chrono::microseconds mWhenGranted{0};
    Permission mPermission{Permission::ReadWrite};
    bool mHasPermission{false};
    bool mHasWhenGranted{false};
};

/// Constructor
SchemaPermission::SchemaPermission() :
    pImpl(std::make_unique<SchemaPermissionImpl> ())
{
}

/// Copy constructor
SchemaPermission::SchemaPermission(const SchemaPermission &schemaPermission)
{
    *this = schemaPermission;
}

/// Move constructor
SchemaPermission::SchemaPermission(SchemaPermission &&schemaPermission) noexcept
{
    *this = std::move(schemaPermission);
}

/// Destructor
SchemaPermission::~SchemaPermission() = default;

/// Copy assignment
SchemaPermission& 
SchemaPermission::operator=(const SchemaPermission &permission)
{
    if (&permission == this){return *this;}
    pImpl = std::make_unique<SchemaPermissionImpl> (*permission.pImpl);
    return *this;
}

/// Move assignment
SchemaPermission&
SchemaPermission::operator=(SchemaPermission &&permission) noexcept
{
    if (&permission == this){return *this;}
    pImpl = std::move(permission.pImpl);
    return *this;
}

/// Schema
void SchemaPermission::setSchema(const std::string &schema)
{
    if (schema.empty()){throw std::invalid_argument("Schema is empty");}
    pImpl->mSchema = schema;
}

std::string SchemaPermission::getSchema() const
{
    if (!hasSchema()){throw std::runtime_error("Schema not set");}
    return pImpl->mSchema;
}

bool SchemaPermission::hasSchema() const noexcept
{
    return !pImpl->mSchema.empty();
}

/// Permission
void SchemaPermission::setPermission(const Permission permission) noexcept
{
    pImpl->mPermission = permission;
    pImpl->mHasPermission = true;
}

SchemaPermission::Permission  SchemaPermission::getPermission() const
{
    if (!hasPermission()){throw std::runtime_error("Permission not set");}
    return pImpl->mPermission;
}

bool SchemaPermission::hasPermission() const noexcept
{
    return pImpl->mHasPermission;
}

/// Granted time
void SchemaPermission::setWhenGranted(
    const std::chrono::microseconds &timestamp) noexcept
{
    pImpl->mWhenGranted = timestamp;
    pImpl->mHasWhenGranted = true;
}

std::chrono::microseconds SchemaPermission::getWhenGranted() const
{
    if (!hasWhenGranted()){throw std::runtime_error("When granted not set");}
    return pImpl->mWhenGranted;
}

bool SchemaPermission::hasWhenGranted() const noexcept
{
    return pImpl->mHasWhenGranted;
}

template<>
UEATAPIV1::ListUsersResponse::SchemaPermission
SchemaPermission::toMessage() const
{
    UEATAPIV1::ListUsersResponse::SchemaPermission result;
    result.set_schema(getSchema());
    *result.mutable_granted()
        = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
             getWhenGranted().count());
    auto permission = getPermission();
    if (permission == SchemaPermission::Permission::ReadOnly)
    {
        result.set_permission(UEATAPIV1::PERMISSION_READ_ONLY);
    }
    else if (permission == SchemaPermission::Permission::ReadWrite)
    {
        result.set_permission(UEATAPIV1::PERMISSION_READ_WRITE);
    }
    else
    {
        throw std::runtime_error("Unhandled permission");
    }
    return result;
}

///---------------------------------Active Key-------------------------------///
class ActiveKey::ActiveKeyImpl
{
public:
    std::string mName;
    std::string mFingerprint;
    std::chrono::microseconds mWhenRegistered{0};
    std::optional<std::chrono::microseconds> mExpiration{std::nullopt};
    std::optional<std::chrono::microseconds> mLastUsed{std::nullopt};
    Algorithm mAlgorithm{Algorithm::ed25519};
    bool mHasWhenRegistered{false};
    bool mHasAlgorithm{false};    
};  

/// Constructor
ActiveKey::ActiveKey() :
    pImpl(std::make_unique<ActiveKeyImpl> ())
{
}

/// Copy constructor
ActiveKey::ActiveKey(const ActiveKey &key)
{
    *this = key;
}

/// Move constructor
ActiveKey::ActiveKey(ActiveKey &&key) noexcept
{
    *this = std::move(key);
}

/// Destructor
ActiveKey::~ActiveKey() = default;

/// Copy assignment
ActiveKey& ActiveKey::operator=(const ActiveKey &key)
{
    if (&key == this){return *this;}
    pImpl = std::make_unique<ActiveKeyImpl> (*key.pImpl);
    return *this;
}

/// Move assignment
ActiveKey& ActiveKey::operator=(ActiveKey &&key) noexcept
{
    if (&key == this){return *this;}
    pImpl = std::move(key.pImpl);
    return *this;
}

/// Algorithm
void ActiveKey::setAlgorithm(const Algorithm algorithm) noexcept
{
    pImpl->mAlgorithm = algorithm;
    pImpl->mHasAlgorithm = true;
}

ActiveKey::Algorithm ActiveKey::getAlgorithm() const
{
    if (!hasAlgorithm()){throw std::runtime_error("Algorithm not set");}
    return pImpl->mAlgorithm;
}

bool ActiveKey::hasAlgorithm() const noexcept
{
    return pImpl->mHasAlgorithm;
}

/// Key name
void ActiveKey::setName(const std::string &name)
{
    if (name.empty())
    {
        throw std::invalid_argument("Key name is empty");
    }
    pImpl->mName = name;
}

std::string ActiveKey::getName() const
{
    if (!hasName()){throw std::runtime_error("Key name not set");}
    return pImpl->mName;
}

bool ActiveKey::hasName() const noexcept
{
    return !pImpl->mName.empty();
}

/// Fingerprint
void ActiveKey::setFingerprint(const std::string &fingerprint)
{
    if (fingerprint.empty())
    {
        throw std::invalid_argument("Fingerprint is empty");
    }
    pImpl->mFingerprint = fingerprint;
}

std::string ActiveKey::getFingerprint() const
{
    if (!hasFingerprint()){throw std::runtime_error("Fingerprint not set");}
    return pImpl->mFingerprint;
}

bool ActiveKey::hasFingerprint() const noexcept
{
    return !pImpl->mFingerprint.empty();
}

/// Registration time
void ActiveKey::setWhenRegistered(const std::chrono::microseconds &timestamp)
{
    if (pImpl->mExpiration != std::nullopt)
    {
        if (*pImpl->mExpiration < timestamp)
        {
            throw std::invalid_argument(
               "Expiration time precedes registration time");
        }
    }
    pImpl->mWhenRegistered = timestamp;
    pImpl->mHasWhenRegistered = true;
}

std::chrono::microseconds ActiveKey::getWhenRegistered() const
{
    if (!hasWhenRegistered())
    {
        throw std::runtime_error("Key registration time not set");
    }
    return pImpl->mWhenRegistered;
}

bool ActiveKey::hasWhenRegistered() const noexcept
{
    return pImpl->mHasWhenRegistered;
}

/// Expiration
void ActiveKey::setExpiration(const std::chrono::microseconds &timestamp)
{
    if (hasWhenRegistered())
    {
        if (timestamp < pImpl->mWhenRegistered)
        {
            throw std::invalid_argument(
               "Expiration cannot precede registration time");
        }
    }
    pImpl->mExpiration
        = std::make_optional<std::chrono::microseconds> (timestamp);
}

std::optional<std::chrono::microseconds>
ActiveKey::getExpiration() const noexcept
{
    return pImpl->mExpiration;
}

/// Last used
void ActiveKey::setLastUsed(const std::chrono::microseconds &timestamp)
{
    pImpl->mLastUsed
        = std::make_optional<std::chrono::microseconds> (timestamp);
}

std::optional<std::chrono::microseconds>
ActiveKey::getLastUsed() const noexcept
{
    return pImpl->mLastUsed;
}

template<>
UEATAPIV1::ListUsersResponse::ActiveKey
ActiveKey::toMessage() const
{
    UEATAPIV1::ListUsersResponse::ActiveKey result;
    result.set_name(getName());
    *result.mutable_registered()
        = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
             getWhenRegistered().count());
    result.set_fingerprint(getFingerprint());
    auto expiration = getExpiration();
    if (expiration != std::nullopt)
    {
        *result.mutable_expires()
            = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
                  expiration->count());
    }
    auto lastUsed = getLastUsed();
    if (lastUsed != std::nullopt)
    {
        *result.mutable_last_used()
            = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
                  lastUsed->count());
    }
    auto algorithm = getAlgorithm(); 
    if (algorithm == ActiveKey::Algorithm::ed25519)
    {   
        result.set_algorithm(
           UEATAPIV1::ListUsersResponse_SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519);
    }   
    else
    {   
        throw std::runtime_error("Unhandled key signature algorithm");
    }   
    return result;
}

///--------------------------------Inactive Key------------------------------///
class InactiveKey::InactiveKeyImpl
{
public:
    std::string mName;
    std::string mFingerprint;
    std::chrono::microseconds mWhenRegistered{0};
    std::chrono::microseconds mWhenInvalidated{0};
    std::optional<std::chrono::microseconds> mLastUsed{std::nullopt};
    Algorithm mAlgorithm{Algorithm::ed25519};
    Reason mReason{Reason::Revoked};
    bool mHasWhenRegistered{false};
    bool mHasWhenInvalidated{false};
    bool mHasAlgorithm{false};
    bool mHasReason{false};
};

/// Constructor
InactiveKey::InactiveKey() :
    pImpl(std::make_unique<InactiveKeyImpl> ()) 
{
}

/// Copy constructor
InactiveKey::InactiveKey(const InactiveKey &key)
{
    *this = key;
}

/// Move constructor
InactiveKey::InactiveKey(InactiveKey &&key) noexcept
{
    *this = std::move(key);
}

/// Destructor
InactiveKey::~InactiveKey() = default;

/// Copy assignment
InactiveKey& InactiveKey::operator=(const InactiveKey &key)
{
    if (&key == this){return *this;}
    pImpl = std::make_unique<InactiveKeyImpl> (*key.pImpl);
    return *this;
}

/// Move assignment
InactiveKey& InactiveKey::operator=(InactiveKey &&key) noexcept
{
    if (&key == this){return *this;}
    pImpl = std::move(key.pImpl);
    return *this;
}

/// Key name
void InactiveKey::setName(const std::string &name)
{
    if (name.empty())
    {
        throw std::invalid_argument("Key name is empty");
    }
    pImpl->mName = name;
}

std::string InactiveKey::getName() const
{
    if (!hasName()){throw std::runtime_error("Key name not set");}
    return pImpl->mName;
}

bool InactiveKey::hasName() const noexcept
{
    return !pImpl->mName.empty();
}

/// Algorithm
void InactiveKey::setAlgorithm(const Algorithm algorithm) noexcept
{
    pImpl->mAlgorithm = algorithm;
    pImpl->mHasAlgorithm = true;
}

InactiveKey::Algorithm InactiveKey::getAlgorithm() const
{
    if (!hasAlgorithm()){throw std::runtime_error("Algorithm not set");}
    return pImpl->mAlgorithm;
}

bool InactiveKey::hasAlgorithm() const noexcept
{
    return pImpl->mHasAlgorithm;
}

/// Fingerprint
void InactiveKey::setFingerprint(const std::string &fingerprint)
{
    if (fingerprint.empty())
    {    
        throw std::invalid_argument("Fingerprint is empty");
    }    
    pImpl->mFingerprint = fingerprint;
}

std::string InactiveKey::getFingerprint() const
{
    if (!hasFingerprint()){throw std::runtime_error("Fingerprint not set");}
    return pImpl->mFingerprint;
}

bool InactiveKey::hasFingerprint() const noexcept
{
    return !pImpl->mFingerprint.empty();
}


/// Reason
void InactiveKey::setReason(const Reason reason) noexcept
{
    pImpl->mReason = reason;
    pImpl->mHasReason = true;
}

InactiveKey::Reason InactiveKey::getReason() const
{
    if (!hasReason()){throw std::runtime_error("Reason not set");}
    return pImpl->mReason;
}

bool InactiveKey::hasReason() const noexcept
{
    return pImpl->mHasReason;
}


/// Last used
void InactiveKey::setLastUsed(const std::chrono::microseconds &timestamp)
{
    pImpl->mLastUsed
        = std::make_optional<std::chrono::microseconds> (timestamp);
}

std::optional<std::chrono::microseconds>
InactiveKey::getLastUsed() const noexcept
{
    return pImpl->mLastUsed;
}

/// Registration time
void InactiveKey::setWhenRegistered(const std::chrono::microseconds &timestamp)
{
    if (hasWhenInvalidated())
    {
        if (getWhenInvalidated() < timestamp)
        {
            throw std::invalid_argument(
               "Invalidation time precedes registration time");
        }
    }
    pImpl->mWhenRegistered = timestamp;
    pImpl->mHasWhenRegistered = true;
}

std::chrono::microseconds InactiveKey::getWhenRegistered() const
{
    if (!hasWhenRegistered())
    {
        throw std::runtime_error("Key registration time not set");
    }
    return pImpl->mWhenRegistered;
}

bool InactiveKey::hasWhenRegistered() const noexcept
{
    return pImpl->mHasWhenRegistered;
}

/// Revocation
void InactiveKey::setWhenInvalidated(const std::chrono::microseconds &timestamp)
{
    if (hasWhenRegistered())
    {
        if (timestamp < pImpl->mWhenRegistered)
        {
            throw std::invalid_argument(
               "Invalidation time cannot precede registration time");
        }
    }
    pImpl->mWhenInvalidated = timestamp;
    pImpl->mHasWhenInvalidated = true;
}

std::chrono::microseconds InactiveKey::getWhenInvalidated() const
{
    if (!hasWhenInvalidated())
    {
        throw std::runtime_error("Invalidation time not set");
    }
    return pImpl->mWhenInvalidated;
}

bool InactiveKey::hasWhenInvalidated() const noexcept
{
    return pImpl->mHasWhenInvalidated;
}

template<>
UEATAPIV1::ListUsersResponse::InactiveKey
InactiveKey::toMessage() const
{
    UEATAPIV1::ListUsersResponse::InactiveKey result;
    result.set_name(getName());
    *result.mutable_registered()
        = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
             getWhenRegistered().count());
    result.set_fingerprint(getFingerprint());
    *result.mutable_invalidated()
        = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
                  getWhenInvalidated().count());
    auto lastUsed = getLastUsed();
    if (lastUsed != std::nullopt)
    {
        *result.mutable_last_used()
            = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
                  lastUsed->count());
    }
    auto algorithm = getAlgorithm();
    if (algorithm == InactiveKey::Algorithm::ed25519)
    {
        result.set_algorithm(
           UEATAPIV1::ListUsersResponse_SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519);
    }
    else
    {
        throw std::runtime_error("Unhandled key signature algorithm");
    }
    auto reason = getReason();
    if (reason == InactiveKey::Reason::Revoked)
    {
        result.set_reason(
           UEATAPIV1::ListUsersResponse_InactiveKey_Reason_REASON_REVOKED);
    }
    else if (reason == InactiveKey::Reason::Expired)
    {
        result.set_reason(
           UEATAPIV1::ListUsersResponse_InactiveKey_Reason_REASON_EXPIRED);
    }
    else
    {
        throw std::runtime_error("Unhandled reason");
    }
    return result;
}


///----------------------------------Active User-----------------------------///

class ActiveUser::ActiveUserImpl
{
public:
    std::vector<SchemaPermission> mSchemaPermissions;
    std::vector<ActiveKey> mActiveKeys;
    std::vector<InactiveKey> mInactiveKeys;
    std::string mName; 
    std::optional<std::chrono::microseconds> mLastLogin{std::nullopt};
    std::chrono::microseconds mWhenCreated{0};
    std::chrono::microseconds mPasswordUpdated{0};
    bool mIsAdministrator{false};
    bool mIsAdministratorSet{false};
    bool mHasWhenCreated{false};
    bool mHasWhenPasswordUpdated{false};
};

/// Constructor
ActiveUser::ActiveUser() :
    pImpl(std::make_unique<ActiveUserImpl> ()) 
{
}   
    
/// Copy constructor
ActiveUser::ActiveUser(const ActiveUser &user)
{
    *this = user;
}

/// Move constructor
ActiveUser::ActiveUser(ActiveUser &&user) noexcept
{
    *this = std::move(user);
}

/// Destructor
ActiveUser::~ActiveUser() = default;

/// Copy assignment
ActiveUser& ActiveUser::operator=(const ActiveUser &user)
{
    if (&user == this){return *this;}
    pImpl = std::make_unique<ActiveUserImpl> (*user.pImpl);
    return *this;
}

/// Move assignment
ActiveUser& ActiveUser::operator=(ActiveUser &&user) noexcept
{
    if (&user == this){return *this;}
    pImpl = std::move(user.pImpl);
    return *this;
}

/// User name
void ActiveUser::setName(const std::string &name)
{
    if (name.empty())
    {   
        throw std::invalid_argument("User name is empty");
    }
    pImpl->mName = name;
}

std::string ActiveUser::getName() const
{
    if (!hasName()){throw std::runtime_error("User name not set");}
    return pImpl->mName;
}

bool ActiveUser::hasName() const noexcept
{
    return !pImpl->mName.empty();
}

/// Administrator status
void ActiveUser::setIsAdministrator() noexcept
{
    pImpl->mIsAdministrator = true;
    pImpl->mIsAdministratorSet = true;
}

void ActiveUser::setIsNotAdministrator() noexcept
{
    pImpl->mIsAdministrator = false;
    pImpl->mIsAdministratorSet = true;
}

bool ActiveUser::isAdministrator() const
{
    if (!wasIsAdministratorSet())
    {
        throw std::runtime_error("Administrator status not set");
    }
    return pImpl->mIsAdministrator;
}

bool ActiveUser::wasIsAdministratorSet() const noexcept
{
    return pImpl->mIsAdministratorSet;
}

/// Creation time
void ActiveUser::setWhenCreated(const std::chrono::microseconds &timestamp)
{
    if (hasWhenPasswordUpdated())
    {
        if (pImpl->mPasswordUpdated < timestamp)
        {
            throw std::invalid_argument(
              "Password update time cannot proceed user creation time");
        }
    }
    pImpl->mWhenCreated = timestamp; 
    pImpl->mHasWhenCreated = true;
}

std::chrono::microseconds ActiveUser::getWhenCreated() const
{
    if (!hasWhenCreated())
    {
        throw std::runtime_error("User creation time not set");
    }
    return pImpl->mWhenCreated;
}

bool ActiveUser::hasWhenCreated() const noexcept
{
    return pImpl->mHasWhenCreated;
} 

/// Password updated
void ActiveUser::setWhenPasswordUpdated(
    const std::chrono::microseconds &timestamp)
{
    if (hasWhenCreated())
    {
        if (timestamp < pImpl->mWhenCreated)
        {
            throw std::invalid_argument(
              "Creation time cannot precede password update time");
        }
    }
    pImpl->mPasswordUpdated = timestamp;
    pImpl->mHasWhenPasswordUpdated = true;
}

std::chrono::microseconds ActiveUser::getWhenPasswordUpdated() const
{
    if (!hasWhenPasswordUpdated())
    {
        throw std::runtime_error("Password update time not set");
    }
    return pImpl->mPasswordUpdated;
}

bool ActiveUser::hasWhenPasswordUpdated() const noexcept
{
    return pImpl->mHasWhenPasswordUpdated;
}    

/// Last login
void ActiveUser::setLastLogin(const std::chrono::microseconds &timestamp)
{
    if (hasWhenCreated())
    {
        if (timestamp < pImpl->mWhenCreated)
        {
            throw std::invalid_argument(
                "Cannot login before account is created");
        }
    }
    pImpl->mLastLogin
        = std::make_optional<std::chrono::microseconds> (timestamp);
}

std::optional<std::chrono::microseconds>
ActiveUser::getLastLogin() const noexcept
{
    return pImpl->mLastLogin;
}

/// Schema permissions
void ActiveUser::setSchemaPermissions(
    std::vector<SchemaPermission> &&permissions)
{
    for (const auto &permission : permissions)
    {
        ::checkSchemaPermission(permission);
    }
    pImpl->mSchemaPermissions = std::move(permissions);
}

std::vector<SchemaPermission> 
ActiveUser::getSchemaPermissions() const noexcept
{
    return pImpl->mSchemaPermissions;
}

/// Active keys
void ActiveUser::setActiveKeys(std::vector<ActiveKey> &&activeKeys)
{
    for (const auto &key : activeKeys)
    {
        ::checkActiveKey(key);
    }
    pImpl->mActiveKeys = std::move(activeKeys);
}

std::vector<ActiveKey> ActiveUser::getActiveKeys() const noexcept
{
    return pImpl->mActiveKeys;
}

/// Inactive keys
void ActiveUser::setInactiveKeys(std::vector<InactiveKey> &&keys)
{
    for (const auto &key : keys)
    {
        ::checkInactiveKey(key);
    }
    pImpl->mInactiveKeys = std::move(keys);
}

std::vector<InactiveKey> ActiveUser::getInactiveKeys() const noexcept
{
    return pImpl->mInactiveKeys;
}

template<>
UEATAPIV1::ListUsersResponse::ActiveUser
ActiveUser::toMessage() const
{
    UEATAPIV1::ListUsersResponse::ActiveUser result;
    result.set_name(getName());
    result.set_administrator(isAdministrator());
    *result.mutable_created()
        = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
             getWhenCreated().count());
    *result.mutable_password_updated()
        = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
             getWhenPasswordUpdated().count());
    auto lastLogin = getLastLogin();
    if (lastLogin != std::nullopt)
    {
        *result.mutable_last_login()
            = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
                 lastLogin->count());
    }
    for (const auto &permission : pImpl->mSchemaPermissions)
    {
        result.mutable_permissions()->Add(
        std::move(
              permission.toMessage
                  <UEATAPIV1::ListUsersResponse::SchemaPermission> ())
        );
    }
    for (const auto &key : pImpl->mActiveKeys)
    {
        result.mutable_active_keys()->Add(
        std::move(
              key.toMessage
                  <UEATAPIV1::ListUsersResponse::ActiveKey> ())
        );
    }
    for (const auto &key : pImpl->mInactiveKeys)
    {
        result.mutable_inactive_keys()->Add(
        std::move(
              key.toMessage
                  <UEATAPIV1::ListUsersResponse::InactiveKey> ())
        );
    }
    return result;
}

///------------------------------Provisional User----------------------------///

class ProvisionalUser::ProvisionalUserImpl
{
public:
    std::vector<SchemaPermission> mSchemaPermissions;
    std::vector<ActiveKey> mActiveKeys;
    std::vector<InactiveKey> mInactiveKeys;
    std::string mName; 
    std::optional<std::chrono::microseconds> mLastLogin{std::nullopt};
    std::chrono::microseconds mWhenCreated{0};
    std::chrono::microseconds mWhenExpired{0};
    bool mIsAdministrator{false};
    bool mIsExpired{false};
    bool mPasswordReset{false};
    bool mIsAdministratorSet{false};
    bool mHasWhenCreated{false};
    bool mHasWhenExpired{false};
    bool mHasIsExpired{false};
    bool mHasPaswordReset{false};
};

/// Constructor
ProvisionalUser::ProvisionalUser() :
    pImpl(std::make_unique<ProvisionalUserImpl> ()) 
{
}   
    
/// Copy constructor
ProvisionalUser::ProvisionalUser(const ProvisionalUser &user)
{
    *this = user;
}

/// Move constructor
ProvisionalUser::ProvisionalUser(ProvisionalUser &&user) noexcept
{
    *this = std::move(user);
}

/// Destructor
ProvisionalUser::~ProvisionalUser() = default;

/// Copy assignment
ProvisionalUser& ProvisionalUser::operator=(const ProvisionalUser &user)
{
    if (&user == this){return *this;}
    pImpl = std::make_unique<ProvisionalUserImpl> (*user.pImpl);
    return *this;
}

/// Move assignment
ProvisionalUser& ProvisionalUser::operator=(ProvisionalUser &&user) noexcept
{
    if (&user == this){return *this;}
    pImpl = std::move(user.pImpl);
    return *this;
}

/// User name
void ProvisionalUser::setName(const std::string &name)
{
    if (name.empty())
    {
        throw std::invalid_argument("User name is empty");
    }
    pImpl->mName = name;
}

std::string ProvisionalUser::getName() const
{
    if (!hasName()){throw std::runtime_error("User name not set");}
    return pImpl->mName;
}

bool ProvisionalUser::hasName() const noexcept
{
    return !pImpl->mName.empty();
}

/// Administrator status
void ProvisionalUser::setIsAdministrator() noexcept
{
    pImpl->mIsAdministrator = true;
    pImpl->mIsAdministratorSet = true;
}

void ProvisionalUser::setIsNotAdministrator() noexcept
{
    pImpl->mIsAdministrator = false;
    pImpl->mIsAdministratorSet = true;
}

bool ProvisionalUser::isAdministrator() const
{
    if (!wasIsAdministratorSet())
    {   
        throw std::runtime_error("Administrator status not set");
    }
    return pImpl->mIsAdministrator;
}

bool ProvisionalUser::wasIsAdministratorSet() const noexcept
{
    return pImpl->mIsAdministratorSet;
}

/// Schema permissions
void ProvisionalUser::setSchemaPermissions(
    std::vector<SchemaPermission> &&permissions)
{
    for (const auto &permission : permissions)
    {
        ::checkSchemaPermission(permission);
    }
    pImpl->mSchemaPermissions = std::move(permissions);
}

std::vector<SchemaPermission> 
ProvisionalUser::getSchemaPermissions() const noexcept
{
    return pImpl->mSchemaPermissions;
}

/// Password expired?
void ProvisionalUser::setExpired() noexcept
{
    pImpl->mIsExpired = true;
    pImpl->mHasIsExpired = true;
}

void ProvisionalUser::setNotExpired() noexcept
{
    pImpl->mIsExpired = false;
    pImpl->mHasIsExpired = true;
}

bool ProvisionalUser::isExpired() const
{
    if (!wasIsExpiredSet())
    {
        throw std::runtime_error("Password reset toggle not set");
    }
    return pImpl->mIsExpired;
}

bool ProvisionalUser::wasIsExpiredSet() const noexcept
{
    return pImpl->mHasIsExpired;
}

void ProvisionalUser::setPasswordReset() noexcept
{
    pImpl->mPasswordReset = true;
    pImpl->mHasPaswordReset = true;
}

void ProvisionalUser::setPasswordNotReset() noexcept
{
    pImpl->mPasswordReset = false;
    pImpl->mHasPaswordReset = true;
}

bool ProvisionalUser::passwordReset() const
{
    if (!wasPasswordResetSet())
    {
        throw std::runtime_error("Password reset status not set");
    }
    return pImpl->mPasswordReset;
}

bool ProvisionalUser::wasPasswordResetSet() const noexcept
{
    return pImpl->mHasPaswordReset;
}

/// Creation time
void ProvisionalUser::setWhenCreated(const std::chrono::microseconds &timestamp)
{
    if (hasExpiration())
    {
        if (pImpl->mWhenExpired < timestamp)
        {
            throw std::invalid_argument(
               "Password update time cannot proceed user creation time");
        }
    }
    pImpl->mWhenCreated = timestamp;
    pImpl->mHasWhenCreated = true;
}

std::chrono::microseconds ProvisionalUser::getWhenCreated() const
{
    if (!hasWhenCreated())
    {
        throw std::runtime_error("User creation time not set");
    }
    return pImpl->mWhenCreated;
}

bool ProvisionalUser::hasWhenCreated() const noexcept
{
    return pImpl->mHasWhenCreated;
}

/// Expiration time
void ProvisionalUser::setExpiration(const std::chrono::microseconds &timestamp)
{
    if (hasWhenCreated())
    {
        if (timestamp < pImpl->mWhenCreated)
        {
            throw std::invalid_argument(
                "Account cannot expire before being created");
        }
    }
    pImpl->mWhenExpired = timestamp;
    pImpl->mHasWhenExpired = true;
}

std::chrono::microseconds ProvisionalUser::getExpiration() const
{
    if (!hasExpiration())
    {    
        throw std::runtime_error("Account expiration time not set");
    }    
    return pImpl->mWhenExpired;
}

bool ProvisionalUser::hasExpiration() const noexcept
{
    return pImpl->mHasWhenExpired;
}

/// Last login
void ProvisionalUser::setLastLogin(const std::chrono::microseconds &timestamp)
{
    if (hasWhenCreated())
    {
        if (timestamp < pImpl->mWhenCreated)
        {
            throw std::invalid_argument(
                "Cannot login before account is created");
        }
    }
    pImpl->mLastLogin
        = std::make_optional<std::chrono::microseconds> (timestamp);
}

std::optional<std::chrono::microseconds>
ProvisionalUser::getLastLogin() const noexcept
{
    return pImpl->mLastLogin;
}

/// Active keys
void ProvisionalUser::setActiveKeys(std::vector<ActiveKey> &&activeKeys)
{
    for (const auto &key : activeKeys)
    {
        ::checkActiveKey(key);
    }
    pImpl->mActiveKeys = std::move(activeKeys);
}

std::vector<ActiveKey> ProvisionalUser::getActiveKeys() const noexcept
{
    return pImpl->mActiveKeys;
}

/// Inactive keys
void ProvisionalUser::setInactiveKeys(std::vector<InactiveKey> &&keys)
{
    for (const auto &key : keys)
    {
        ::checkInactiveKey(key);
    }
    pImpl->mInactiveKeys = std::move(keys);
}

std::vector<InactiveKey> ProvisionalUser::getInactiveKeys() const noexcept
{
    return pImpl->mInactiveKeys;
}

template<>
UEATAPIV1::ListUsersResponse::ProvisionalUser
ProvisionalUser::toMessage() const
{
    UEATAPIV1::ListUsersResponse::ProvisionalUser result;
    result.set_name(getName());
    result.set_administrator(isAdministrator());
    *result.mutable_created()
        = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
             getWhenCreated().count());
    *result.mutable_expiration()
        = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
             getExpiration().count());
    result.set_expired(isExpired());
    result.set_password_reset(passwordReset());
    auto lastLogin = getLastLogin();
    if (lastLogin != std::nullopt)
    {
        *result.mutable_last_login()
            = google::protobuf::util::TimeUtil::MicrosecondsToTimestamp(
                 lastLogin->count());
    }
    for (const auto &permission : pImpl->mSchemaPermissions)
    {
        result.mutable_permissions()->Add(
        std::move(
              permission.toMessage
                  <UEATAPIV1::ListUsersResponse::SchemaPermission> ())
        );
    }
    for (const auto &key : pImpl->mActiveKeys)
    {
        result.mutable_active_keys()->Add(
        std::move(
              key.toMessage
                  <UEATAPIV1::ListUsersResponse::ActiveKey> ())
        );
    }
    for (const auto &key : pImpl->mInactiveKeys)
    {
        result.mutable_inactive_keys()->Add(
        std::move(
              key.toMessage
                  <UEATAPIV1::ListUsersResponse::InactiveKey> ())
        );
    }
    return result;
}

///---------------------------------User List--------------------------------///

class UserList::UserListImpl
{
public:
    std::vector<ActiveUser> mActiveUsers;
    std::vector<ProvisionalUser> mProvisionalUsers;
};

/// Constructor
UserList::UserList() :
    pImpl(std::make_unique<UserListImpl> ())
{
}

/// Copy constructor
UserList::UserList(const UserList &list)
{
    *this = list;
}

/// Move constructor
UserList::UserList(UserList &&list) noexcept
{
    *this = std::move(list);
}

/// Destructor
UserList::~UserList() = default;

/// Copy assignment
UserList& UserList::operator=(const UserList &list)
{
    if (&list == this){return *this;}
    pImpl = std::make_unique<UserListImpl> (*list.pImpl);
    return *this;
}

/// Move assignment
UserList& UserList::operator=(UserList &&list) noexcept
{
    if (&list == this){return *this;}
    pImpl = std::move(list.pImpl);
    return *this;
}

/// Active users
void UserList::setActiveUsers(std::vector<ActiveUser> &&users)
{
    // Check requisite fields set
    for (const auto &user : users)
    {
        ::checkActiveUser(user);
    }
    // Should be enough now to check a unique constraint on user names
    std::set<std::string> existingUsers;
    for (const auto &user : pImpl->mProvisionalUsers)
    {
        existingUsers.insert(user.getName());
    }
    for (const auto &user : users)
    {
        if (existingUsers.contains(user.getName()))
        {
            throw std::invalid_argument(user.getName() + " already exists");
        }
        existingUsers.insert(user.getName());
    }
    pImpl->mActiveUsers = std::move(users);
}

std::vector<ActiveUser>
UserList::getActiveUsers() const
{
    return pImpl->mActiveUsers;
}

const std::vector<ActiveUser>
&UserList::getActiveUsersReference() const noexcept
{
    return *&pImpl->mActiveUsers;
}

/// Provisional users
void UserList::setProvisionalUsers(
    std::vector<ProvisionalUser> &&users)
{
    // Check requisite fields set
    for (const auto &user : users)
    {
        ::checkProvisionalUser(user);
    }
    // Should be enough now to check a unique constraint on user names
    std::set<std::string> existingUsers;
    for (const auto &user : pImpl->mActiveUsers)
    {
        existingUsers.insert(user.getName());
    }
    for (const auto &user : users)
    {
        if (existingUsers.contains(user.getName()))
        {
            throw std::invalid_argument(user.getName() + " already exists");
        }
        existingUsers.insert(user.getName());
    }
    pImpl->mProvisionalUsers = std::move(users);
}

std::vector<ProvisionalUser> 
UserList::getProvisionalUsers() const
{
    return pImpl->mProvisionalUsers;
}

const std::vector<ProvisionalUser> 
&UserList::getProvisionalUsersReference() const noexcept
{
    return *&pImpl->mProvisionalUsers;
}

