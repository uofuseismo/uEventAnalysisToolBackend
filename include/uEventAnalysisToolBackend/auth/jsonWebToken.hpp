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
/// @brief Handles the JSON webtoken utility as an authenticator.
class JSONWebToken : public IAuthenticator
{
public:
    enum class Algorithm
    {
        EdDSA25519  /*!< Edwards curve cryptography. */
    };
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
    /// @brief Initialize for an unsigned algorithm.
    explicit JSONWebToken(std::shared_ptr<spdlog::logger> logger);

    /// @brief Initialize for a signed algorithm.
    /// @note You can generate a private key with something like:
    ///       openssl genpkey -algorithm ed25519 -out ed25519-private-key.pem
    ///       and a corresonding public key with something like
    ///       openssl pkey -in ed25519-private-key.pem -pubout -out ed25519-public-key.pem
    ///       The keys are then secrets in Kubernetes.
    JSONWebToken(const std::pair<std::string, std::string> &publicAndPrivateKey,
                 std::shared_ptr<spdlog::logger> logger);
 
    /// @brief Perform the bearer authentication on this JWT.
    [[nodiscard]] IAuthenticator::Result authenticateBearer(const std::string &jwt) final;

    /// @result True indicates the this will a signature algorithm.
    [[nodiscard]] bool isSigned() const noexcept;

    /// @brief Creates a token for the user.
    [[nodiscard]] std::string createToken(const std::string &user) const;
    /// @brief Creates a token for the user with embedded permissions.
    /// @note The permissions ride in the signed payload; a client cannot
    ///       alter them without invalidating the signature.
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
