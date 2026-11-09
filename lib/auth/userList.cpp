#include <chrono>
#include <memory>
#include <optional>
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

///-------------------------------Schema Permission--------------------------///
 
class SchemaPermission::SchemaPermissionImpl
{
public:
    std::string mSchema;
    std::chrono::microseconds mWhenGranted;
    Permission mPermission;
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
    std::chrono::microseconds mWhenRegistered;
    std::optional<std::chrono::microseconds> mExpiration{std::nullopt};
    std::optional<std::chrono::microseconds> mLastUsed{std::nullopt};
    Algorithm mAlgorithm;
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
    if (!hasName()){throw std::runtime_error("Fingerprint not set");}
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
               "Registration time precedes expiration time");
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

///--------------------------------Revoked Key-------------------------------///
class InactiveKey::InactiveKeyImpl
{
public:
    std::string mName;
    std::string mFingerprint;
    std::chrono::microseconds mWhenRegistered;
    std::chrono::microseconds mWhenInvalidated;
    std::optional<std::chrono::microseconds> mLastUsed{std::nullopt};
    Algorithm mAlgorithm;
    Reason mReason;
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
               "Registration time precedes invalidation time");
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

///----------------------------------Active User-----------------------------///

class ActiveUser::ActiveUserImpl
{
public:
    std::vector<SchemaPermission> mSchemaPermissions;
    std::vector<ActiveKey> mActiveKeys;
    std::vector<InactiveKey> mInactiveKeys;
    std::string mName; 
    std::optional<std::chrono::microseconds> mLastLogin{std::nullopt};
    std::chrono::microseconds mWhenCreated;
    bool mIsAdministrator;
    bool mIsAdministratorSet{false};
    bool mHasWhenCreated{false};
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

/// Last login
void ActiveUser::setLastLogin(const std::chrono::microseconds &timestamp)
{
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
    pImpl->mActiveKeys = std::move(activeKeys);
}

std::vector<ActiveKey> ActiveUser::getActiveKeys() const noexcept
{
    return pImpl->mActiveKeys;
}

/// Revoked keys
void ActiveUser::setInactiveKeys(std::vector<InactiveKey> &&keys)
{
    for (const auto &key : keys)
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
    pImpl->mInactiveKeys = std::move(keys);
}

std::vector<InactiveKey> ActiveUser::getInactiveKeys() const noexcept
{
    return pImpl->mInactiveKeys;
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
    std::chrono::microseconds mWhenCreated;
    std::chrono::microseconds mWhenExpired;
    bool mIsAdministrator;
    bool mIsAdministratorSet{false};
    bool mHasWhenCreated{false};
    bool mHasExpired{false};
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

