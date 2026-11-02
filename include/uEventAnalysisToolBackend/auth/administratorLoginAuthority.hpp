#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_ADMINISTRATOR_LOGIN_AUTHORITY_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_ADMINISTRATOR_LOGIN_AUTHORITY_HPP
#include <expected>
#include <memory>
#include <utility>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/authenticator.hpp>
namespace UEventAnalysisToolBackend::Auth
{
 class AdministratorLoginAuthorityOptions;
}
namespace UEventAnalysisToolBackend::Auth
{
/// @class AdministratorLoginAuthority administratroLoginAuthority.hpp
/// @brief Converts credentials into tokens for user administrator login
///        attempts.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class AdministratorLoginAuthority
{
public:
    /// @brief Constructor.
    /// @param[in] options   The login authority options.
    /// @param[in] logger    The application logger.
    /// @throws std::invalid_argument if the database is null, the
    ///         algorithm is unsigned, or there is no private key.
    AdministratorLoginAuthority(const AdministratorLoginAuthorityOptions &options,
                                std::shared_ptr<spdlog::logger> logger); 

    /// @result True indicates the class is initialized.
    [[nodiscard]] bool isInitialized() const noexcept;

    /// @brief Password login.
    /// @param[in] userNameAndPassword  The user name (first) and password
    ///                                 (second). 
    /// @result On success, this mints a new administrator token - i.e., this is
    ///         not a user claim.  
    [[nodiscard]] std::expected<std::string, IAuthenticator::Result>
        loginWithPassword(const std::pair<std::string, std::string> &userNameAndPassword) const;
 
    /// @brief Destructor
    ~AdministratorLoginAuthority();

    AdministratorLoginAuthority() = delete;
    AdministratorLoginAuthority(const AdministratorLoginAuthority &) = delete;
    AdministratorLoginAuthority(AdministratorLoginAuthority &&) noexcept = delete;
    AdministratorLoginAuthority& operator=(const AdministratorLoginAuthority &) = delete;
    AdministratorLoginAuthority& operator=(AdministratorLoginAuthority &&) noexcept = delete;
private:
    class AdministratorLoginAuthorityImpl;
    std::unique_ptr<AdministratorLoginAuthorityImpl> pImpl;
};
}
#endif
