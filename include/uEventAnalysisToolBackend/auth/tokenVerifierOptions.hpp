#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_TOKEN_VERIFIER_OPTIONS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_TOKEN_VERIFIER_OPTIONS_HPP
#include <chrono>
#include <memory>

namespace UEventAnalysisToolBackend::Auth
{

/// @class TokenVerifierOptions tokenVerifierOptions.hpp
/// @brief Defines the options for the token verifier.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
/// @note This cannot mint tokens.
class TokenVerifierOptions
{
public:
    /// @brief The token signing algorithm.
    enum class Algorithm
    {
        EdDSA25519  /*!< The token is signed with the Edwards-curve
                         ed25519 algorithm. */
    };
public:
    /// @brief Constructor.
    TokenVerifierOptions();
    /// @brief Copy constructor.
    TokenVerifierOptions(const TokenVerifierOptions &options);
    /// @brief Move constructor.
    TokenVerifierOptions(TokenVerifierOptions &&options) noexcept; 

    /// @brief Sets the public key and corresponding algorithm.
    /// @throws std::invalid_argument if the public key is empty.
    void setPublicKeyAndAlgorithm(const std::string &publicKey, const Algorithm algorithm);
    /// @result The public key.
    /// @throws std::invalid_argument if hasPublicKeyAndAlgorithm() is false.
    [[nodiscard]] std::string getPublicKey() const;
    /// @result The signature algorithm.
    /// @throws std::runtime_error if \c hasPublicKeyAndAlgorithm() is false.
    [[nodiscard]] Algorithm getAlgorithm() const;
    /// @result True indicates that the public key was set.
    [[nodiscard]] bool hasPublicKeyAndAlgorithm() const noexcept;

    /// @brief Sets the issuer.
    /// @param[in] issuer   The token issuer.
    /// @throws std::invalid-argument if the issuer is empty.
    void setIssuer(const std::string &issuer);
    /// @result The issuer.
    /// @throws std::invalid_argument if \c hasIssuer() is false.
    [[nodiscard]] std::string getIssuer() const;
    /// @result True indicates that the issuer was set.
    [[nodiscard]] bool hasIssuer() const noexcept;

    /// @brief Sets the clock leeway in the token validation.
    /// @param[in] leeway   The clock leeway for the JWT validator.
    /// @throws std::invalid_argument if this is not positive.
    void setClockLeeway(const std::chrono::seconds &leeway);
    /// @result The clock leeway.
    /// @note By default this is 0.
    [[nodiscard]] std::chrono::seconds getClockLeeway() const noexcept;

    /// @brief Destructor.
    ~TokenVerifierOptions();
    /// @brief Copy assignment.
    TokenVerifierOptions &operator=(const TokenVerifierOptions &options);
    /// @brief Move assignment.
    TokenVerifierOptions &operator=(TokenVerifierOptions &&options) noexcept;

private:
    class TokenVerifierOptionsImpl;
    std::unique_ptr<TokenVerifierOptionsImpl> pImpl;
};
}
#endif
