#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_JWT_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_JWT_HPP
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/authenticator.hpp>

namespace UEventAnalysisToolBackend::Auth
{
 class JSONWebTokenOptions;
}

namespace UEventAnalysisToolBackend::Auth
{
/// @brief Handles the JSON webtoken utility as an authenticator.
class JSONWebToken : public IAuthenticator
{
public:
    /// @brief The verified contents of a token.
    struct Claims
    {
        /// The authenticated user.
        std::string user;
        /// The (schema, permission) pairs granted to the user - e.g.,
        /// ("utah", "read_write").
        std::vector<std::pair<std::string, std::string>> permissions;
    };
public:
    /// @brief Constructor.
    /// @param[in] options  The token authority policy: signing algorithm,
    ///                     signing key pair, and token time-to-live.  The
    ///                     key pair is required unless the algorithm is
    ///                     Unsigned.
    /// @param[in] logger   The application logger.
    /// @throws std::invalid_argument if a signing algorithm is selected but
    ///         the options carry no key pair.
    JSONWebToken(const JSONWebTokenOptions &options,
                 std::shared_ptr<spdlog::logger> logger);

    /// @brief Perform the bearer authentication on this JWT.
    [[nodiscard]] IAuthenticator::Result authenticateBearer(const std::string &jwt) final;

    /// @result True indicates the this will a signature algorithm.
    [[nodiscard]] bool isSigned() const noexcept;

    /// @brief Creates a token for the user.
    [[nodiscard]] std::string createToken(const std::string &user) const;
    /// @brief Creates a token for the user with embedded permissions.
    /// @note The permissions ride in the signed payload; a client cannot
    ///       alter them without invalidating the signature.  The token's
    ///       lifetime is fixed by the authority's options.
    [[nodiscard]] std::string createToken(const std::string &user,
        const std::vector<std::pair<std::string, std::string>> &permissions) const;

    /// @brief Verifies the token and unpacks its claims.
    /// @result The authentication result and, on Authenticated, the claims.
    [[nodiscard]] std::pair<IAuthenticator::Result, std::optional<Claims>>
        verify(const std::string &jwt) const;

    /// @brief Destructor.
    ~JSONWebToken();

    JSONWebToken() = delete;
    JSONWebToken(const JSONWebToken &) = delete;
    JSONWebToken(JSONWebToken &&) noexcept = delete;
    JSONWebToken& operator=(const JSONWebToken &) = delete;
    JSONWebToken& operator=(JSONWebToken &&) noexcept = delete;
private:
    class JSONWebTokenImpl;
    std::unique_ptr<JSONWebTokenImpl> pImpl;
};
}
#endif
