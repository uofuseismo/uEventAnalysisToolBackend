#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <boost/json/object.hpp>
#include <boost/json/value.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class UserTokenVerifier::UserTokenVerifierImpl
{
public:
    UserTokenVerifierImpl(
        const TokenVerifierOptions &options,
        std::shared_ptr<spdlog::logger> logger) :
        mOptions(options),
        mLogger(std::move(logger))
    {
        if (!mOptions.hasIssuer())
        {
            throw std::runtime_error("Issuer not set");
        }
        if (!mOptions.hasPublicKeyAndAlgorithm())
        {
            throw std::runtime_error("Public key and algorithm not set");
        }
        mIssuer = mOptions.getIssuer();
        mPublicKey = mOptions.getPublicKey();
        if (mOptions.getAlgorithm() !=
            TokenVerifierOptions::Algorithm::EdDSA25519)
        {
            throw std::runtime_error("Only EdDSA25519 supported");
        }
        if (mLogger == nullptr)
        {
            // NOLINTBEGIN(misc-include-cleaner)
            constexpr const char *loggerName{"UserTokenVerifierConsole"};
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
        mInitialized = true;
    }

    /// @brief Verify the token and unpack its claims.
    [[nodiscard]]
    std::pair<IAuthenticator::Result, std::optional<Claims>>
    verify(const std::string &token) const
    {
        if (!mInitialized)
        {
            SPDLOG_LOGGER_ERROR(mLogger, "UserTokenVerifier not initialized");
            return {IAuthenticator::Result::ServerError, std::nullopt};
        }
        try
        {
            auto decodedToken
                = jwt::decode<jwt::traits::boost_json> (token);
            auto verifier
                = jwt::verify<jwt::traits::boost_json> ()
                    .with_issuer(mOptions.getIssuer())
                    .leeway(mOptions.getClockLeeway().count());
            verifier.allow_algorithm(jwt::algorithm::ed25519(
                    mPublicKey,
                    mPrivateKey,
                    mPublicKeyPassword,
                    mPrivateKeyPassword));
            // Verify it 
            std::error_code errorCode;
            verifier.verify(decodedToken, errorCode);
            if (errorCode)
            {
                SPDLOG_LOGGER_WARN(mLogger,
                                   "Verification failed because {}",
                                   errorCode.message());
                return {IAuthenticator::Result::InvalidCredentials,
                        std::nullopt};
            }
            try 
            {
                std::vector<std::pair<std::string, std::string>> permissions;
                auto user = decodedToken.get_subject();
                auto expiresAt = decodedToken.get_expires_at();
                constexpr Claims::Scope scope{Claims::Scope::User};
                auto scopeString
                    = decodedToken.get_payload_claim("scope").as_string();
                if (scopeString != "user")
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                                       "Invalid scope {}", scopeString); 
                    return {IAuthenticator::Result::InvalidCredentials,
                            std::nullopt};
                }
                const std::string permissionsClaim{"permissions"};
                if (decodedToken.has_payload_claim(permissionsClaim))
                {
                    const auto permissionsObject
                        = decodedToken.get_payload_claim(
                              std::string {permissionsClaim})
                             .to_json().as_object();
                    permissions.reserve(permissionsObject.size());
                    for (const auto &item : permissionsObject)
                    {
                        permissions.emplace_back(
                            std::string {item.key()},
                            std::string {item.value().as_string()});
                    }
                }
                Claims claims
                {
                    user,
                    scope,
                    std::move(permissions),
                    expiresAt
                };
                SPDLOG_LOGGER_INFO(mLogger, "Verified {}", claims.getUser());
                return {IAuthenticator::Result::Authenticated,
                        std::move(claims)};
            }
            catch (const std::exception &e) 
            {
                SPDLOG_LOGGER_ERROR(mLogger,
                                    "Could not extract claims because {}",
                                    std::string {e.what()});
                return {IAuthenticator::Result::ServerError, std::nullopt};
            }
        }
        catch (const std::exception &e)
        {
            SPDLOG_LOGGER_WARN(mLogger,
                               "Could not decode token because {}",
                               e.what());
            return {IAuthenticator::Result::InvalidCredentials, std::nullopt};
        }

    }
//private:
    TokenVerifierOptions mOptions;
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    std::string mIssuer;
    std::string mPublicKey;
    const std::string mPrivateKey{""}; // Not necessary here 
    const std::string mPublicKeyPassword{""}; // Not impelemented
    const std::string mPrivateKeyPassword{""}; // Not necessary here
    bool mInitialized{false};
};

/// Constructor
UserTokenVerifier::UserTokenVerifier(
    const TokenVerifierOptions &options,
    std::shared_ptr<spdlog::logger> logger) :
    pImpl(std::make_unique<UserTokenVerifierImpl> (options, std::move(logger)))
{
}

/// Copy constructor
UserTokenVerifier::UserTokenVerifier(const UserTokenVerifier &verifier)
{
    *this = verifier;
}

/// Move constructor
UserTokenVerifier::UserTokenVerifier(UserTokenVerifier &&verifier) noexcept
{
    *this = std::move(verifier);
}

/// Copy assignment
UserTokenVerifier 
&UserTokenVerifier::operator=(const UserTokenVerifier &verifier)
{
    if (&verifier == this){return *this;}
    pImpl = std::make_unique<UserTokenVerifierImpl> (*verifier.pImpl);
    return *this;
}

/// Move assignment
UserTokenVerifier 
&UserTokenVerifier::operator=(UserTokenVerifier &&verifier) noexcept
{
    if (&verifier == this){return *this;}
    pImpl = std::move(verifier.pImpl);
    return *this;
}

/// Destructor
UserTokenVerifier::~UserTokenVerifier() = default;

/// Initialized?
bool UserTokenVerifier::isInitialized() const noexcept
{
    return pImpl->mInitialized;
}

/// Verify
std::pair<IAuthenticator::Result, std::optional<Claims>>
UserTokenVerifier::verify(const std::string &jwt) const
{
    return pImpl->verify(jwt);
}
