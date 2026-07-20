#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_JSON_WEB_TOKEN_OPTIONS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_JSON_WEB_TOKEN_OPTIONS_HPP
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>

namespace UEventAnalysisToolBackend::Auth
{
/// @class JSONWebTokenOptions jsonWebTokenOptions.hpp
/// @brief The set-once policy for a JSON web token authority: which signing
///        algorithm it uses and how long the tokens it mints are valid.
///        The backend fixes these at startup and never flips them, so they
///        belong here rather than on each createToken call.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class JSONWebTokenOptions
{
public:
    /// @brief The token signing algorithm.
    enum class Algorithm
    {
        Unsigned,   /*!< The token is not signed (algorithm none). */
        EdDSA25519  /*!< The token is signed with the Edwards-curve
                         ed25519 algorithm. */
    };
public:
    /// @brief Constructor.
    JSONWebTokenOptions();
    /// @brief Copy constructor.
    JSONWebTokenOptions(const JSONWebTokenOptions &options);
    /// @brief Move constructor.
    JSONWebTokenOptions(JSONWebTokenOptions &&options) noexcept;

    /// @brief Sets how long a token is valid for after it is issued.
    /// @param[in] timeToLive  The token lifetime.
    /// @throws std::invalid_argument if timeToLive is not positive - that
    ///         would mint a token that is already expired.
    void setTimeToLive(const std::chrono::seconds &timeToLive);
    /// @result The token time-to-live.  Defaults to 15 minutes.
    [[nodiscard]] std::chrono::seconds getTimeToLive() const noexcept;

    /// @brief Sets the signing algorithm.
    void setAlgorithm(Algorithm algorithm) noexcept;
    /// @result The signing algorithm.  Defaults to EdDSA25519.
    [[nodiscard]] Algorithm getAlgorithm() const noexcept;

    /// @brief Sets the public and private signing key pair.  This is
    ///        required for any signing algorithm and ignored when the
    ///        algorithm is Unsigned.
    /// @param[in] publicAndPrivateKey  .first is the public key and
    ///                                 .second is the private key.
    /// @throws std::invalid_argument if either key is empty.
    void setKeyPair(const std::pair<std::string, std::string> &publicAndPrivateKey);
    /// @result The public and private key pair.
    /// @throws std::runtime_error if \c hasKeyPair() is false.
    [[nodiscard]] std::pair<std::string, std::string> getKeyPair() const;
    /// @result True indicates the key pair was set.
    [[nodiscard]] bool hasKeyPair() const noexcept;

    /// @brief Creates JWT options from an initialization file.
    /// @param[in] file     The ini file path.
    /// @param[in] section  The section of the ini file to read e.g. 
    ///                     to read the [Authentication] section specify
    ///                     "Authentication".
    static JSONWebTokenOptions fromInitializationFile(const std::filesystem::path &file,
                                                      const std::string &section = "Authentication");

    /// @brief Destructor.
    ~JSONWebTokenOptions();
    /// @brief Copy assignment.
    JSONWebTokenOptions& operator=(const JSONWebTokenOptions &options);
    /// @brief Move assignment.
    JSONWebTokenOptions& operator=(JSONWebTokenOptions &&options) noexcept;
private:
    class JSONWebTokenOptionsImpl;
    std::unique_ptr<JSONWebTokenOptionsImpl> pImpl;
};
}
#endif
