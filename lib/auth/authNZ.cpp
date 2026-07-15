#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include "uEventAnalysisToolBackend/auth/authNZ.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/database.hpp"
#include "uEventAnalysisToolBackend/auth/jsonWebToken.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class AuthNZ::AuthNZImpl
{
private:
    /// @brief Gets (or creates on first use) the console logger for
    ///        this class.
    [[nodiscard]] static std::shared_ptr<spdlog::logger> makeConsoleLogger()
    {
        // NOLINTBEGIN(misc-include-cleaner)
        constexpr const char *loggerName{"AuthNZConsole"};
        auto logger = spdlog::get(loggerName);
        if (logger == nullptr)
        {
            logger = spdlog::stdout_color_mt(loggerName);
        }
        return logger;
        // NOLINTEND(misc-include-cleaner)
    }
public:
    AuthNZImpl(std::unique_ptr<Database> &&databaseAuthenticator,
               std::unique_ptr<JSONWebToken> &&tokenAuthority,
               std::shared_ptr<spdlog::logger> logger) :
        mDatabase(std::move(databaseAuthenticator)),
        mTokenAuthority(std::move(tokenAuthority)),
        mLogger(std::move(logger))
    {
        if (mDatabase == nullptr)
        {
            throw std::invalid_argument("Database authenticator is null");
        }
        if (mTokenAuthority == nullptr)
        {
            throw std::invalid_argument("Token authority is null");
        }
        if (!mTokenAuthority->isSigned())
        {
            throw std::invalid_argument(
                "Token authority must sign tokens - permissions on an "
                "unsigned token could be forged by the client");
        }
        if (mLogger == nullptr){mLogger = makeConsoleLogger();}
    }

    std::unique_ptr<Database> mDatabase{nullptr};
    std::unique_ptr<JSONWebToken> mTokenAuthority{nullptr};
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
};

/// Constructor
AuthNZ::AuthNZ(std::unique_ptr<Database> &&databaseAuthenticator,
               std::unique_ptr<JSONWebToken> &&tokenAuthority,
               std::shared_ptr<spdlog::logger> logger) :
    pImpl(std::make_unique<AuthNZImpl> (std::move(databaseAuthenticator),
                                        std::move(tokenAuthority),
                                        std::move(logger)))
{
}

/// Login: basic authentication then a token with the user's permissions
std::pair<IAuthenticator::Result, std::string>
AuthNZ::login(const std::pair<std::string, std::string> &userNameAndPassword)
{
    const auto &user = userNameAndPassword.first;
    if (user.empty()){throw std::invalid_argument("User is empty");}
    auto result = pImpl->mDatabase->authenticateBasic(userNameAndPassword);
    if (result != IAuthenticator::Result::Authenticated)
    {
        return {result, std::string {}};
    }
    // Bake the permissions into the signed token.  Note, a user with no
    // permissions can still log in - they just can't do anything.
    try
    {
        auto permissions = pImpl->mDatabase->getPermissions(user);
        auto token = pImpl->mTokenAuthority->createToken(user, permissions);
        return {IAuthenticator::Result::Authenticated, std::move(token)};
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to issue token for {} because {}",
                            user, std::string {e.what()});
        return {IAuthenticator::Result::ServerError, std::string {}};
    }
}

/// The per-RPC bearer check
std::pair<IAuthenticator::Result, std::optional<JSONWebToken::Claims>>
AuthNZ::authenticate(const std::string &jwt) const
{
    return pImpl->mTokenAuthority->verify(jwt);
}

/// The authorization check
bool AuthNZ::isAuthorized(const JSONWebToken::Claims &identity,
                          const std::string &schema,
                          const std::string &permission) noexcept
{
    for (const auto &[grantedSchema, grantedPermission] :
         identity.permissions)
    {
        if (grantedSchema == schema)
        {
            if (grantedPermission == permission){return true;}
            // Writers can read.
            if (permission == "read_only" &&
                grantedPermission == "read_write")
            {
                return true;
            }
        }
    }
    return false;
}

/// Destructor
AuthNZ::~AuthNZ() = default;
