#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LOGIN_AUTHORITY_OPTIONS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LOGIN_AUTHORITY_OPTIONS_HPP
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
namespace UEventAnalysisToolBackend::Database
{
 class Credentials;
}
namespace UEventAnalysisToolBackend::Auth
{
 namespace Password
 {
  class HasherOptions;
  class PasswordPolicy;
 }
}
namespace UEventAnalysisToolBackend::Auth
{
/// @class UserLoginAuthorityOptions loginAuthorityOptions.hpp
/// @brief Options defining the user login authority.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class UserLoginAuthorityOptions
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
    UserLoginAuthorityOptions();
    /// @brief Copy constructor.
    UserLoginAuthorityOptions(const UserLoginAuthorityOptions &options);
    /// @brief Move constructor.
    UserLoginAuthorityOptions(UserLoginAuthorityOptions &&options) noexcept;

    /// @brief Sets the credentials for forming a database connection. 
    /// @throws std::invalid_argument if the user, password, or database
    ///         name is not set.
    void setDatabaseCredentials(
        const UEventAnalysisToolBackend::Database::Credentials &credentials);
    /// @result The database connection credentials.
    /// @throws std::runtime_error if \c hasDatabaseCredentials() is false.
    [[nodiscard]] UEventAnalysisToolBackend::Database::Credentials getDatabaseCredentials() const;
    /// @result True indicates that the credentials were set.
    [[nodiscard]] bool hasDatabaseCredentials() const noexcept;

    /// @brief Sets the password hasher options.
    void setPasswordHasherOptions(const Password::HasherOptions &options);
    /// @result The password hasher options.
    [[nodiscard]] Password::HasherOptions getPasswordHasherOptions() const noexcept;

    /// @brief Sets the password policy.
    void setPasswordPolicy(const Password::PasswordPolicy &policy);
    /// @result The password policy.
    [[nodiscard]] Password::PasswordPolicy getPasswordPolicy() const noexcept;

    /// @brief Sets the issuer.
    /// @param[in] issuer   The token issuer.
    /// @throws std::invalid_argument if the issuer is empty.
    void setIssuer(const std::string &issuer);
    /// @result The issuer.
    /// @throws std::invalid_argument if \c hasIssuer() is false.
    [[nodiscard]] std::string getIssuer() const;
    /// @result True indicates that the issuer was set.
    [[nodiscard]] bool hasIssuer() const noexcept;
  
    /// @brief Sets the public and private key for signing the generated token
    ///        as well as the signing algorithm.
    /// @param[in] publicAndPrivateKey  The public and private key for signing
    ///                                 the token.
    /// @param[in] algorithm  The signing algorithm.
    /// @throws std::invalid_argument if the public or private key are empty
    ///         or the public or private key are the same. 
    void setKeyPairAndAlgorithm(const std::pair<std::string, std::string> &publicAndPrivateKey,
                                Algorithm algorithm);
    /// @result The keys.
    /// @throws std::runtime_error if \c hasKeyPairAndAlgorithm() is false.
    [[nodiscard]] std::pair<std::string, std::string> getKeyPair() const;
    /// @result The signing algorithm.
    /// @throws std::runtime_error if \c hasKeyPairAndAlgorithm() is false.
    [[nodiscard]] Algorithm getAlgorithm() const;
    /// @result True indicates the keys and algorithm was set.
    [[nodiscard]] bool hasKeyPairAndAlgorithm() const noexcept;
  
    /// @brief Sets how long a token is valid for after it is issued.
    /// @param[in] timeToLive  The token lifetime.
    /// @throws std::invalid_argument if timeToLive is not positive - that
    ///         would mint a token that is already expired.
    void setTimeToLive(const std::chrono::seconds &timeToLive);
    /// @result The token time-to-live.
    /// @throws std::runtime_error if \c hasTimeToLive() is false.
    [[nodiscard]] std::chrono::seconds getTimeToLive() const;
    /// @result True indicates that the token time to live was set. 
    [[nodiscard]] bool hasTimeToLive() const noexcept;

    /// @brief Destructor.
    ~UserLoginAuthorityOptions();

    /// @brief Copy assignment.
    UserLoginAuthorityOptions &operator=(const UserLoginAuthorityOptions &options);
    /// @brief Move assignment.
    UserLoginAuthorityOptions &operator=(UserLoginAuthorityOptions &&options) noexcept;

    /// @brief Loads the user login authority options from an ini file.
    [[nodiscard]] static UserLoginAuthorityOptions 
        fromInitializationFile(const std::filesystem::path &iniFile,
                               const std::string &section,
                               const std::string &defaultIssuer);
private:
    class UserLoginAuthorityOptionsImpl;
    std::unique_ptr<UserLoginAuthorityOptionsImpl> pImpl;
};
}
#endif
