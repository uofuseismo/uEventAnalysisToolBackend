#include <algorithm>
#include <cctype>
#include <exception>
#include <expected>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include "uEventAnalysisToolBackend/auth/userAdministration.hpp"
#include "uEventAnalysisToolBackend/auth/userAdministrationOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolBackend/database/credentials.hpp"
#include "databaseUtilities.hpp"

using namespace UEventAnalysisToolBackend::Auth;

namespace
{

[[nodiscard]] 
std::string transform(const std::string &nameIn)
{
    auto maximumLength
        = static_cast<size_t>
          (UserAdministrationOptions::getMaximumUserNameLength());
    const auto isSpace = [](const unsigned char c)
                         {
                             return std::isspace(c) != 0;
                         };
    auto first = std::ranges::find_if_not(nameIn, isSpace);
    auto last = std::ranges::find_if_not(nameIn.rbegin(), nameIn.rend(),
                                         isSpace).base();
    if (first >= last){return {};}
    std::string name{first, last};
    if (name.size() > maximumLength){return {};}
    for (auto &c : name)
    {
        const auto lowered
            = static_cast<char> (std::tolower(static_cast<unsigned char> (c)));
        const auto isAllowed = (lowered >= 'a' && lowered <= 'z')
                            || (lowered >= '0' && lowered <= '9')
                            || lowered == '.' || lowered == '_'
                            || lowered == '-' || lowered == '@';
        if (!isAllowed){return {};}
        c = lowered;
    }
    return name;
}


/// @result The schema as auth.schemas stores it: trimmed and lower-cased.
///         Empty if it is not a plausible schema name, so the caller
///         can refuse it without asking the database.
[[nodiscard]] std::string normalizeSchema(const std::string &schemaIn)
{
    // Postgres truncates identifiers at 63 bytes (NAMEDATALEN - 1).
    constexpr std::size_t maximumLength{63};
    const auto isSpace = [](const unsigned char c)
                         {
                             return std::isspace(c) != 0;
                         };
    auto first = std::ranges::find_if_not(schemaIn, isSpace);
    auto last = std::ranges::find_if_not(schemaIn.rbegin(), schemaIn.rend(),
                                         isSpace).base();
    if (first >= last){return {};}
    std::string schema{first, last};
    if (schema.size() > maximumLength){return {};}
    for (auto &c : schema)
    {
        const auto lowered
            = static_cast<char> (std::tolower(static_cast<unsigned char> (c)));
        const auto isAllowed = (lowered >= 'a' && lowered <= 'z')
                            || (lowered >= '0' && lowered <= '9')
                            || lowered == '_';
        if (!isAllowed){return {};}
        c = lowered;
    }
    return schema;
}

std::string enumToString(const UserAdministration::Permission permission)
{
    if (permission == UserAdministration::Permission::ReadOnly)
    {
        return "read_only";
    }
    else if (permission == UserAdministration::Permission::ReadWrite)
    {
        return "read_write";
    }
    throw std::runtime_error("Unhandled logic");
}

[[nodiscard]] std::string_view toString(const UserAdministration::ReturnCode code)
{
    using ReturnCode = UserAdministration::ReturnCode;
    if (code == ReturnCode::Success)
    {
        return "success";
    }
    else if (code == ReturnCode::InvalidArgument)
    {
        return "invalid argument";
    }
    else if (code == ReturnCode::NoUserFound)
    {
        return "no such user";
    }
    else if (code == ReturnCode::NoSchema)
    {
        return "no such schema";
    }
    else if (code == ReturnCode::AlreadyExists)
    {
        return "user already exists";
    }
    else if (code == ReturnCode::NotAuthorized)
    {
        return "actor is not an administrator";
    }
    else if (code == ReturnCode::LastAdministrator)
    {
        return "would leave no administrator";
    }
    else if (code == ReturnCode::ServerError)
    {
        return "server error";
    }
    return "unknown";
}

}

class UserAdministration::UserAdministrationImpl : 
    public Detail::DatabaseConnection::Database
{
public:
    UserAdministrationImpl(
        const UserAdministrationOptions &options,
        std::shared_ptr<spdlog::logger> logger) :
        Detail::DatabaseConnection::Database
        {
            "UserAdministrationConsole",
            options.getDatabaseCredentials(),
            std::move(logger)
        },
        mOptions(options)
    {
        mPasswordHasher
             = std::make_unique<Password::Hasher>
               (mOptions.getPasswordHasherOptions());
        mInitialized = true;
    }

    /// @brief Runs one gated admin call that returns BOOLEAN.
    /// @result The boolean, or the error the database raised.
    [[nodiscard]] std::expected<bool, ReturnCode>
        callAdminFunction(std::string_view query,
                           const pqxx::params &parameters)
    {
        try
        {
            return withTransaction<pqxx::work>(
                [&](pqxx::work &transaction) -> bool
                {
                    const auto ok
                        = transaction.exec(query, parameters).one_row()[0]
                                                             .as<bool> ();
                    transaction.commit();
                    return ok;
                });
        }
        catch (const pqxx::insufficient_privilege &)
        {
            return std::unexpected(ReturnCode::NotAuthorized);
        }
        catch (const pqxx::sql_error &e)
        {
            if (e.sqlstate() == "55006")
            {
                return std::unexpected(ReturnCode::LastAdministrator);
            }
            if (e.sqlstate() == "22023")
            {
                return std::unexpected(ReturnCode::NoSchema);
            }
            throw;
        }
    }

/*
    void listUsers()
    {
        constexpr std::string_view query{"auth.list_users()"};
        try
        {
            return withTransaction<pqxx::read_transaction>(
                [&](pqxx::read_transaction &transaction) -> bool
                {
                    const auto ok
                        = transaction.exec(query).one_row()[0]
                                                 .as<bool> (); 
                    transaction.commit();
                    return ok; 
                });
        }
        catch (const pqxx::insufficient_privilege &)
        {
            return std::unexpected(ReturnCode::NotAuthorized);
        }
        catch (const pqxx::sql_error &e) 
        {
            if (e.sqlstate() == "55006")
            {
                return std::unexpected(ReturnCode::LastAdministrator);
            }
            // TODO should this be servererror?
            throw;
        }
        return std::unexpected(ReturnCode::ServerError);
    }
*/

    //NOLINTBEGIN(bugprone-easily-swappable-parameters)
    [[nodiscard]]
    std::expected<bool, ReturnCode> 
        createProvisionalUser(const std::string &actor,
                              const std::string &name,
                              const std::string &hashedPassword)
    //NOLINTEND(bugprone-easily-swappable-parameters)
    {
        auto interval = mOptions.getIssuedPasswordTimeToLive().count();
        constexpr std::string_view query
        {
           "SELECT auth.admin_add_provisional_user($1, $2, $3, make_interval(secs => $4))"
        };
        const pqxx::params parameters{actor, name, hashedPassword, interval};
        return callAdminFunction(query, parameters); 
    }

    //NOLINTBEGIN(bugprone-easily-swappable-parameters)
    [[nodiscard]]
    std::expected<bool, ReturnCode> 
        deleteUser(const std::string &actor, const std::string &name)
    //NOLINTEND(bugprone-easily-swappable-parameters)
    {   
        constexpr std::string_view query
        {
           "SELECT auth.admin_remove_user($1, $2)"
        };
        const pqxx::params parameters{actor, name};
        return callAdminFunction(query, parameters); 
    }

    //NOLINTBEGIN(bugprone-easily-swappable-parameters)
    [[nodiscard]]
    std::expected<bool, ReturnCode> 
        revokePermission(const std::string &actor,
                         const std::string &name,
                         const std::string &schema)
    //NOLINTEND(bugprone-easily-swappable-parameters)
    {
        constexpr std::string_view query
        {
           "SELECT auth.admin_revoke_user_permission($1, $2, $3)"
        };
        const pqxx::params parameters{actor, name, schema};
        return callAdminFunction(query, parameters); 
    }

    //NOLINTBEGIN(bugprone-easily-swappable-parameters)
    [[nodiscard]]
    std::expected<bool, ReturnCode> 
        setAdministrator(const std::string &actor,
                         const std::string &name,
                         const bool toAdministrator)
    //NOLINTEND(bugprone-easily-swappable-parameters)
    {
        constexpr std::string_view query
        {
           "SELECT auth.admin_set_user_admin($1, $2, $3)"
        };
        const pqxx::params parameters{actor, name, toAdministrator};
        return callAdminFunction(query, parameters); 
    }

    //NOLINTBEGIN(bugprone-easily-swappable-parameters)
    [[nodiscard]]
    std::expected<bool, ReturnCode>
        setPermission(const std::string &actor,
                      const std::string &name,
                      const std::string &schema,
                      const std::string &permission)
    //NOLINTEND(bugprone-easily-swappable-parameters)
    {
        constexpr std::string_view query
        {   
           "SELECT auth.admin_set_user_permission($1, $2, $3, $4)"
        };
        const pqxx::params parameters{actor, name, schema, permission};
        return callAdminFunction(query, parameters);
    }

    //NOLINTBEGIN(bugprone-easily-swappable-parameters)
    [[nodiscard]]
    std::expected<bool, ReturnCode> 
        resetPassword(const std::string &actor,
                      const std::string &name,
                      const std::string &hashedPassword,
                      const bool revokeKeys)
    //NOLINTEND(bugprone-easily-swappable-parameters)
    {   
        auto interval = mOptions.getIssuedPasswordTimeToLive().count();
        constexpr std::string_view query
        {
           "SELECT auth.admin_reset_user_password($1, $2, $3, make_interval(secs => $4), $5)"
        };
        const pqxx::params parameters{actor, name, hashedPassword,
                                      interval, revokeKeys};
        return callAdminFunction(query, parameters); 
    }   


//private:
    UserAdministrationOptions mOptions;
    std::unique_ptr<Password::Hasher> mPasswordHasher{nullptr};
    bool mInitialized{false};
};

/// Constructor
UserAdministration::UserAdministration(
    const UserAdministrationOptions &options,
    std::shared_ptr<spdlog::logger> logger) :
    pImpl(std::make_unique<UserAdministrationImpl> (options, std::move(logger)))
{
}

/// Initialized?
bool UserAdministration::isInitialized() const noexcept
{
    return pImpl->mInitialized;
}

/// Create a provisional user
std::expected<UserAdministration::IssuedPassword,
              UserAdministration::ReturnCode>
UserAdministration::createProvisionalUser(const std::string &actorIn,
                                          const std::string &nameIn)
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "User administration class not initialized");
        return std::unexpected(ReturnCode::ServerError);
    }

    auto actor = ::transform(actorIn);
    if (actor.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Actor is empty or invalid");
        return std::unexpected(ReturnCode::InvalidArgument);
    }

    auto name = ::transform(nameIn);
    if (name.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "User name is empty or invalid");
        return std::unexpected(ReturnCode::InvalidArgument);
    }

    std::string issuedPassword;
    try
    {
        auto policy = pImpl->mOptions.getPasswordPolicy();
        issuedPassword = policy.createTemporaryPassword();
        if (issuedPassword.empty())
        {
            throw std::runtime_error("Issued password is empty");
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to create password to issue because {}",
                            e.what());
        return std::unexpected(ReturnCode::ServerError);
    }

    std::string hashedPassword;
    try
    {
        hashedPassword = pImpl->mPasswordHasher->hash(issuedPassword);
    }
    catch (const std::exception &e) 
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to hash temporary password because {}",
                            e.what()); 
        return std::unexpected(ReturnCode::ServerError);
    }

    try
    {
        auto result = pImpl->createProvisionalUser(actor, name, hashedPassword);
        if (result.has_value())
        {
            if (*result)
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                                   "{} created provisional user {}",
                                   actor, name);
            }
            else
            {
                SPDLOG_LOGGER_WARN(pImpl->mLogger,
                                   "User {} already exists",
                                   name);
                return std::unexpected(ReturnCode::AlreadyExists);
            }
        }
        else
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
                               "{} could not add user {}: {}",
                               actor, name, ::toString(result.error()));
            return std::unexpected(result.error());
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to create provisional user because {}",
                            e.what());
        return std::unexpected(ReturnCode::ServerError);
    }

    IssuedPassword result{name, issuedPassword};
    return result;
}

/// Reset a password
std::expected<UserAdministration::IssuedPassword,
              UserAdministration::ReturnCode>
UserAdministration::resetPassword(const std::string &actorIn,
                                  const std::string &nameIn,
                                  const bool revokeKeys)
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "User administration class not initialized");
        return std::unexpected(ReturnCode::ServerError);
    }

    auto actor = ::transform(actorIn);
    if (actor.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Actor is empty or invalid");
        return std::unexpected(ReturnCode::InvalidArgument);
    }

    auto name = ::transform(nameIn);
    if (name.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "User name is empty or invalid");
        return std::unexpected(ReturnCode::InvalidArgument);
    }

    std::string issuedPassword;
    try 
    {
        auto policy = pImpl->mOptions.getPasswordPolicy();
        issuedPassword = policy.createTemporaryPassword();
        if (issuedPassword.empty())
        {   
            throw std::runtime_error("Issued password is empty");
        }   
    }
    catch (const std::exception &e) 
    {   
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to create password to issue because {}",
                            e.what());
        return std::unexpected(ReturnCode::ServerError);
    }   

    std::string hashedPassword;
    try
    {
        hashedPassword = pImpl->mPasswordHasher->hash(issuedPassword);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to hash temporary password because {}",
                            e.what()); 
        return std::unexpected(ReturnCode::ServerError);
    }                       

    try                           
    {                             
        auto result
            = pImpl->resetPassword(actor, name, hashedPassword,
                                   revokeKeys);
        if (result.has_value())
        {
            if (*result)
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                                   "{} reset password for user {}",
                                   actor, name);
            }
            else
            {
                SPDLOG_LOGGER_WARN(pImpl->mLogger,
                                   "User {} does not exist",
                                   name);
                return std::unexpected(ReturnCode::NoUserFound);
            }
        }
        else
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
                               "{} could not reset password for {}: {}",
                               actor, name, ::toString(result.error()));
            return std::unexpected(result.error());
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to reset password for {} because {}",
                            name, e.what());
        return std::unexpected(ReturnCode::ServerError);
    }

    IssuedPassword result{name, issuedPassword};
    return result;                 
}

/// Remove a user
UserAdministration::ReturnCode
UserAdministration::deleteUser(const std::string &actorIn,
                               const std::string &nameIn)
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "User administration class not initialized");
        return ReturnCode::ServerError;
    }

    auto actor = ::transform(actorIn);
    if (actor.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Actor is empty or invalid");
        return ReturnCode::InvalidArgument;
    }   

    auto name = ::transform(nameIn);
    if (name.empty())      
    {   
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "User name is empty or invalid");
        return ReturnCode::InvalidArgument;
    }

    try
    {
        auto result = pImpl->deleteUser(actor, name);
        if (result.has_value())
        {
            if (*result)
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                                   "{} removed user {}",
                                   actor, name);
                return ReturnCode::Success; 
            }
            else
            {
                SPDLOG_LOGGER_WARN(pImpl->mLogger,
                                   "User {} does not exist",
                                   name);
                return ReturnCode::NoUserFound;
            }
        }
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "{} could not remove {}: {}",
                            actor, name, ::toString(result.error()));
        return result.error();
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to remove {} because {}",
                            name, e.what());
        return ReturnCode::ServerError;
    }
}

/// Set a user as an admin
UserAdministration::ReturnCode
UserAdministration::setAdministrator(const std::string &actorIn,
                                     const std::string &nameIn)
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "User administration class not initialized");
        return ReturnCode::ServerError;
    }

    auto actor = ::transform(actorIn);
    if (actor.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Actor is empty or invalid");
        return ReturnCode::InvalidArgument;
    }

    auto name = ::transform(nameIn);
    if (name.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "User name is empty or invalid");
        return ReturnCode::InvalidArgument;
    }

    try                                
    {
        constexpr bool toAdministrator{true};
        auto result = pImpl->setAdministrator(actor, name, toAdministrator);
        if (result.has_value())
        {
            if (*result)
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                                   "{} set user {} to admin",
                                   actor, name);
                return ReturnCode::Success;
            }
            else
            {
                SPDLOG_LOGGER_WARN(pImpl->mLogger,
                                   "User {} does not exist",
                                   name);
                return ReturnCode::NoUserFound;
            }
        }
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "{} could not set {} as an admin: {}",
                           actor, name, ::toString(result.error()));
        return result.error();
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to set {} as admin because {}",
                            name, e.what());
        return ReturnCode::ServerError;
    }
}

/// Revoke admin privs from a user
UserAdministration::ReturnCode
UserAdministration::revokeAdministrator(const std::string &actorIn,
                                        const std::string &nameIn)
{
    if (!isInitialized())
    {   
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "User administration class not initialized");
        return ReturnCode::ServerError;
    }   

    auto actor = ::transform(actorIn);
    if (actor.empty())
    {   
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Actor is empty or invalid");
        return ReturnCode::InvalidArgument;
    }   

    auto name = ::transform(nameIn);
    if (name.empty())
    {   
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "User name is empty or invalid");
        return ReturnCode::InvalidArgument;
    }   

    try                                
    {
        constexpr bool toAdministrator{false};
        auto result = pImpl->setAdministrator(actor, name, toAdministrator);
        if (result.has_value())
        {
            if (*result)
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                                   "{} unset user {} as admin",
                                   actor, name);
                return ReturnCode::Success;
            }
            else
            {
                SPDLOG_LOGGER_WARN(pImpl->mLogger,
                                   "User {} does not exist",
                                   name);
                return ReturnCode::NoUserFound;
            }
        }
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "{} could not unset {} from admin: {}",
                            actor, name, ::toString(result.error()));
        return result.error();
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to unset {} as admin because {}",
                            name, e.what());
        return ReturnCode::ServerError;
    }
}

/// Set permissions for user
UserAdministration::ReturnCode
UserAdministration::setPermission(const std::string &actorIn,
                                  const std::string &nameIn,
                                  const std::string &schemaIn,
                                  const Permission permissionEnum)
{
    if (!isInitialized())
    {   
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "User administration class not initialized");
        return ReturnCode::ServerError;
    }   

    auto actor = ::transform(actorIn);
    if (actor.empty())
    {   
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Actor is empty or invalid");
        return ReturnCode::InvalidArgument;
    }   

    auto name = ::transform(nameIn);
    if (name.empty())
    {   
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "User name is empty or invalid");
        return ReturnCode::InvalidArgument;
    }

    auto schema = ::normalizeSchema(schemaIn);
    if (schema.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Schema is empty or invalid");
        return ReturnCode::NoSchema;
    }

    try                                 
    {
        auto permission = ::enumToString(permissionEnum);
        auto result = pImpl->setPermission(actor, name, schema, permission);
        if (result.has_value())
        {
            if (*result)
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                    "{} changed permissions of user {} in {} to {}",
                    actor, name, schema, permission);
                return ReturnCode::Success;
            }
            else
            {
                SPDLOG_LOGGER_WARN(
                    pImpl->mLogger,
                    "{} failed to change permission for {} in {} to {}",
                    actor, name, schema, permission);
                return ReturnCode::NoUserFound;
            }
        }
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                    "{} could not change permissions for {} in schema {}: {}",
                    actor, name, schema, ::toString(result.error()));
        return result.error();
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger, 
                            "Failed to change permission for {} because {}",
                            name, e.what());
        return ReturnCode::ServerError;
    }
}

/// Revoke permissions for user
UserAdministration::ReturnCode
UserAdministration::revokePermission(const std::string &actorIn,
                                     const std::string &nameIn,
                                     const std::string &schemaIn)
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "User administration class not initialized");
        return ReturnCode::ServerError;
    }

    auto actor = ::transform(actorIn);
    if (actor.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Actor is empty or invalid");
        return ReturnCode::InvalidArgument;
    }   

    auto name = ::transform(nameIn);
    if (name.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "User name is empty or invalid");
        return ReturnCode::InvalidArgument;
    }

    auto schema = ::normalizeSchema(schemaIn);
    if (schema.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Schema is empty or invalid");
        return ReturnCode::NoSchema;
    }

    try                       
    {
        auto result = pImpl->revokePermission(actor, name, schema);
        if (result.has_value())
        {
            if (*result)
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                                   "{} revoked permissions of {} in {}",
                                   actor, name, schema);
                return ReturnCode::Success;
            }
            else
            {
                SPDLOG_LOGGER_WARN(
                    pImpl->mLogger,
                    "{} failed to revoke permission for {} in {}",
                    actor, name, schema);
                return ReturnCode::NoUserFound;
            }
        }
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "{} could not revoke permission for {} in {}: {}",
                            actor, name, schema, ::toString(result.error()));
        return result.error();
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to revoke permission for {} because {}",
                            name, e.what());
        return ReturnCode::ServerError;
    }
}

/// Destructor
UserAdministration::~UserAdministration() = default;
