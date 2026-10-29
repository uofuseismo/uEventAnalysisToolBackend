#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_ADMINISTRATOR_TOKEN_VERIFIER_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_ADMINISTRATOR_TOKEN_VERIFIER_HPP
#include <expected>
#include <memory>
#include <string_view>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/authenticator.hpp>
#include <uEventAnalysisToolBackend/auth/claims.hpp>

namespace UEventAnalysisToolBackend::Auth
{
 class TokenVerifierOptions;
}

namespace UEventAnalysisToolBackend::Auth
{
/// @class UserTokenVerifier userTokenVerifier.hpp
/// @brief Verifies bearer tokens and authorizes the caller solely from the
///        claims.  This is not to be used in the admin service.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
/// @note This cannot mint tokens.
class AdministratorTokenVerifier
{
public:
    /// @param[in] options  The algorithm, public key, expected issuer,
    ///                     and clock leeway.
    /// @param[in] logger   The application logger.
    /// @throws std::invalid_argument if \c hasAlgorithm() is false
    ///         or \c hasPublicKey() is false.
    AdministratorTokenVerifier(const TokenVerifierOptions &options,
                               std::shared_ptr<spdlog::logger> logger);
    /// @brief Copy constructor.
    AdministratorTokenVerifier(const AdministratorTokenVerifier &verifier);
    /// @brief Move constructor.
    AdministratorTokenVerifier(AdministratorTokenVerifier &&verifier) noexcept; 

    /// @result True indicates that the class is initialized.
    [[nodiscard]] bool isInitialized() const noexcept;

    /// @brief Checks the signature, expiry, and issuer.
    /// @result The authentication result and, if successful, the corresponding
    ///         claims.
    [[nodiscard]] std::pair<IAuthenticator::Result, std::optional<Claims>> verify(const std::string &jwt) const;

    /// @param[in] claims      The claims.
    /// @param[in] schema      The schema.
    /// @param[in] permission  The desired permission.
    /// @result True if the claims are a user token whose permission on
    ///         the schema meets the requirement.
    /// @note read_write satisifies read_only.
    [[nodiscard]] static bool isAuthorized(const Claims &claims,
                                           std::string_view schema,
                                           std::string_view permission) noexcept;

    /// @brief Destructor.
    ~AdministratorTokenVerifier();
    /// @brief Copy assignment.
    AdministratorTokenVerifier& operator=(const AdministratorTokenVerifier &tokenVerifier);
    /// @brief Move assignment.
    AdministratorTokenVerifier& operator=(AdministratorTokenVerifier &&tokenVerifier) noexcept;
    AdministratorTokenVerifier() = delete;
private:
    class AdministratorTokenVerifierImpl;
    std::unique_ptr<AdministratorTokenVerifierImpl> pImpl;
};
}
#endif
