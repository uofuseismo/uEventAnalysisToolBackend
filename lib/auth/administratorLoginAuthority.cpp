#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <stdexcept>
#include <utility>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/database.hpp"
// NOLINTNEXTLINE(misc-include-cleaner)
#include "uEventAnalysisToolBackend/auth/databaseOptions.hpp"
#include "uEventAnalysisToolBackend/auth/loginAuthorityOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class AdministratorLoginAuthority::AdministratorLoginAuthorityImpl
{
public:
    AdministratorLoginAuthorityImpl(
        const LoginAuthorityOptions &options,
        std::shared_ptr<spdlog::logger> logger) :
        mOptions(options),
        mLogger(std::move(logger))
    {
        if (!mOptions.hasDatabaseCredentials())
        {
            throw std::invalid_argument("Auth database credentials not set");
        }
        if (!mOptions.hasKeyPairAndAlgorithm())
        {
            throw std::invalid_argument("Key pair and algorithm not set");
        }
        if (!mOptions.hasIssuer())
        {
            throw std::invalid_argument("Issuer not set");
        }
        if (!mOptions.hasTimeToLive())
        {
            throw std::invalid_argument("Time-to-live not set");
        }
        if (mLogger == nullptr)
        {
            // NOLINTBEGIN(misc-include-cleaner)
            constexpr const char *loggerName
            {
                "AdministratorLoginAdministratorConsole"
            };
            // N.B. stdout_color_mt throws if the name is already registered.
            auto loggerHandle = spdlog::get(loggerName);
            if (loggerHandle == nullptr)
            {
                mLogger = spdlog::stdout_color_mt(loggerName);
            }
            else
            {
                mLogger = loggerHandle;
            }
            // NOLINTEND(misc-include-cleaner)
        }
/*
        mDatabase
            = std::make_unique<Database>
              (mOptions.getDatabaseOptions(), mLogger);
*/
        mInitialized = true;
    }

    /// @brief Creates the token; permissions, when present, ride in the
    ///        signed payload.
    [[nodiscard]] std::string createToken(const std::string &user) const
    {
        const std::chrono::seconds expiration{mOptions.getTimeToLive()};
        auto token = jwt::create<jwt::traits::boost_json> ();
        token.set_subject(user)
             .set_issuer(mOptions.getIssuer())
             .set_type("JWT")
             .set_issued_now()
             .set_expires_in(expiration);
        token.set_payload_claim("scope", "administrator");
        if (mOptions.getAlgorithm() ==
            LoginAuthorityOptions::Algorithm::EdDSA25519)
        {
            const std::string publicKeyPassword{""};
            const std::string privateKeyPassword{""};
            auto [publicKey, privateKey] = mOptions.getKeyPair();
            return token.sign(jwt::algorithm::ed25519(
                                  publicKey,
                                  privateKey,
                                  publicKeyPassword,
                                  privateKeyPassword));
        }
        else
        {
            throw std::runtime_error("Only eddsa25519 implemented");
        }
    }

    LoginAuthorityOptions mOptions;
    std::unique_ptr<Database> mDatabase{nullptr};
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    bool mInitialized{false};
};

/// Constructor
AdministratorLoginAuthority::AdministratorLoginAuthority
(
    const LoginAuthorityOptions &options,
    std::shared_ptr<spdlog::logger> logger
) :
    pImpl(std::make_unique<AdministratorLoginAuthorityImpl> 
             (
                 options,
                 std::move(logger)
             )
         )
{
}

/// Initialized?
bool AdministratorLoginAuthority::isInitialized() const noexcept
{
    return pImpl->mInitialized;
}

/// Login with password and get a token
std::expected<std::string, IAuthenticator::Result>
AdministratorLoginAuthority::loginWithPassword(
    const std::pair<std::string, std::string> &userNameAndPassword) const
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "AdministratorLoginAuthority not initialized");
        return std::unexpected(IAuthenticator::Result::ServerError);
    }
    const auto &user = userNameAndPassword.first;
    if (user.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                         "Rejecting admin login attempt because user is empty");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
    // Check against database
    try
    {
/*
        auto result = pImpl->mDatabase->authenticateBasic(userNameAndPassword);
        if (result == IAuthenticator::Result::Authenticated)
        {
            // Create the JWT
            try
            {
                return pImpl->createToken(user); 
            }
            catch (const std::exception &e)
            {
                SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                    "Failed to create token for {} because {}",
                                    user, e.what());
                return std::unexpected(IAuthenticator::Result::ServerError);
            }
        }
        return std::unexpected(result);
*/
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Database failure {} when authentcating {}",
                           e.what(), user);
        return  std::unexpected(IAuthenticator::Result::ServerError);
    } 
}

/// Destructor
AdministratorLoginAuthority::~AdministratorLoginAuthority() = default;
