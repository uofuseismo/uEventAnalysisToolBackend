#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
#include <boost/json/object.hpp>
#include <boost/json/value.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include "uEventAnalysisToolBackend/auth/jsonWebToken.hpp"
#include "uEventAnalysisToolBackend/auth/jsonWebTokenOptions.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"

using namespace UEventAnalysisToolBackend::Auth;

namespace
{
/// The payload claim carrying the (schema, permission) grants.
constexpr std::string_view PERMISSIONS_CLAIM{"permissions"};
}

class JSONWebToken::JSONWebTokenImpl
{
private:
    /// @brief Gets (or creates on first use) the console logger for
    ///        this class.
    [[nodiscard]] static std::shared_ptr<spdlog::logger> makeConsoleLogger()
    {
        // NOLINTBEGIN(misc-include-cleaner)
        constexpr const char *loggerName{"JWTAuthConsole"};
        // N.B. stdout_color_mt throws if the name is already registered.
        auto logger = spdlog::get(loggerName);
        if (logger == nullptr)
        {
            logger = spdlog::stdout_color_mt(loggerName);
        }
        return logger;
        // NOLINTEND(misc-include-cleaner)
    }
public:
    JSONWebTokenImpl(const JSONWebTokenOptions &options,
                     std::shared_ptr<spdlog::logger> logger) :
        mLogger(std::move(logger)),
        mExpirationDuration(options.getTimeToLive()),
        mSignToken(options.getAlgorithm()
                   != JSONWebTokenOptions::Algorithm::Unsigned)
    {
        if (mSignToken)
        {
            if (!options.hasKeyPair())
            {
                throw std::invalid_argument(
                    "A signing key pair is required for a signing algorithm");
            }
            mPublicAndPrivateKey = options.getKeyPair();
        }
        if (mLogger == nullptr){mLogger = makeConsoleLogger();}
    }

    /// @brief Creates the token; permissions, when present, ride in the
    ///        signed payload.
    [[nodiscard]] std::string createToken(const std::string &user,
        const std::vector<std::pair<std::string, std::string>> &permissions) const
    {
        auto token = jwt::create<jwt::traits::boost_json> ();
        token.set_subject(user)
             .set_issuer(mIssuer)
             .set_type("JWT")
             .set_issued_now()
             .set_expires_in(mExpirationDuration);
        if (!permissions.empty())
        {
            boost::json::object permissionsObject;
            for (const auto &[schema, permission] : permissions)
            {
                permissionsObject[schema] = permission;
            }
            token.set_payload_claim(
                std::string {PERMISSIONS_CLAIM},
                jwt::basic_claim<jwt::traits::boost_json>
                    {boost::json::value {permissionsObject}});
        }
        if (mSignToken)
        {
            return token.sign(jwt::algorithm::ed25519(
                                  mPublicAndPrivateKey.first,
                                  mPublicAndPrivateKey.second,
                                  mPublicKeyPassword,
                                  mPrivateKeyPassword));
        }
        return token.sign(jwt::algorithm::none {});
    }

    /// @brief Verify the token and unpack its claims.
    [[nodiscard]]
    std::pair<IAuthenticator::Result, std::optional<JSONWebToken::Claims>>
        verify(const std::string &token) const
    {
        try
        {
            // Decoding throws on a malformed token - that is the
            // client's problem.
            auto decodedToken = jwt::decode<jwt::traits::boost_json> (token);
            auto verifier
                = jwt::verify<jwt::traits::boost_json> ()
                    .with_issuer(mIssuer);
            if (mSignToken)
            {
                verifier.allow_algorithm(jwt::algorithm::ed25519(
                    mPublicAndPrivateKey.first,
                    mPublicAndPrivateKey.second,
                    mPublicKeyPassword,
                    mPrivateKeyPassword));
            }
            else
            {
                verifier.allow_algorithm(jwt::algorithm::none {});
            }
            // N.B. This verify overload does not throw; failures (bad
            // signature, expired token, wrong issuer, disallowed algorithm)
            // are reported through the error code.
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
                JSONWebToken::Claims claims;
                claims.user = decodedToken.get_subject();
                if (decodedToken.has_payload_claim(
                        std::string {PERMISSIONS_CLAIM}))
                {
                    const auto permissionsObject
                        = decodedToken.get_payload_claim(
                              std::string {PERMISSIONS_CLAIM})
                             .to_json().as_object();
                    claims.permissions.reserve(permissionsObject.size());
                    for (const auto &item : permissionsObject)
                    {
                        claims.permissions.emplace_back(
                            std::string {item.key()},
                            std::string {item.value().as_string()});
                    }
                }
                SPDLOG_LOGGER_INFO(mLogger, "Verified {}", claims.user);
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

    /// Don't need this
    JSONWebTokenImpl() = delete;
    JSONWebTokenImpl(const JSONWebTokenImpl &) = delete;
    JSONWebTokenImpl& operator=(const JSONWebTokenImpl &) = delete;

    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    std::string mIssuer{"uEventAnalysisBackendTool"};
    std::chrono::seconds mExpirationDuration{std::chrono::minutes {15}};
    std::pair<std::string, std::string> mPublicAndPrivateKey;
    std::string mPublicKeyPassword{""};
    std::string mPrivateKeyPassword{""};
    bool mSignToken{false};
};

/// Constructor
JSONWebToken::JSONWebToken(const JSONWebTokenOptions &options,
                          std::shared_ptr<spdlog::logger> logger) :
    pImpl(std::make_unique<JSONWebTokenImpl> (options, std::move(logger)))
{
}

/// Generate a token
std::string JSONWebToken::createToken(const std::string &user) const
{
    return createToken(user, {});
}

std::string JSONWebToken::createToken(const std::string &user,
    const std::vector<std::pair<std::string, std::string>> &permissions) const
{
    if (user.empty())
    {
        throw std::invalid_argument("User is empty");
    }
    return pImpl->createToken(user, permissions);
}

/// Verify and unpack
std::pair<IAuthenticator::Result, std::optional<JSONWebToken::Claims>>
JSONWebToken::verify(const std::string &jwt) const
{
    if (jwt.empty()){throw std::invalid_argument("JWT is empty");}
    return pImpl->verify(jwt);
}

/// Auth the user
IAuthenticator::Result JSONWebToken::authenticateBearer(
    const std::string &jwt)
{
    return verify(jwt).first;
}

/// Signed?
bool JSONWebToken::isSigned() const noexcept
{
    return pImpl->mSignToken;
}

/// Destructor
JSONWebToken::~JSONWebToken() = default;
