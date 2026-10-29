#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_CLAIMS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_CLAIMS_HPP
#include <chrono>
#include <string>
#include <utility>
#include <vector>
namespace UEventAnalysisToolBackend::Auth
{
/// @class Claims claims.hpp
/// @brief The verified contents of a token.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class Claims
{
private:
    using ClaimsType = std::vector<std::pair<std::string, std::string>>;
public:
    using const_iterator = typename ClaimsType::const_iterator;
    /// Make the iterator read-only
    using iterator = const_iterator;
public:
    /// @brief Defines the scope of a token.
    enum class Scope
    {
        User,           /*!< Allows schema permissions but no administration privileges. */
        Administrator   /*!< A step-up token for admin RPCs only.  No schmea permissions. */
    };
public:
    /// @brief Builds the claims from information in the JWT.
    /// @param[in] user     The user name.
    /// @param[in] scope    The claim's scope - e.g., User or Adminsistrator?
    /// @param[in,out] permissions  The permissions to various namespaces 
    ///                             - e.g., { (utah, read-write), (ynp, read-only) }.
    ///                             On exit, the behavior of permissions is undefined.
    /// @param[in] expiresAt    When the JWT expires.
    Claims(const std::string &user,
           const Scope scope,
           std::vector<std::pair<std::string, std::string>> &&permissions, 
           const std::chrono::system_clock::time_point &expiresAt) :
        mPermissions(std::move(permissions)),
        mUser(user),
        mScope(scope),
        mExpiresAt(expiresAt)
    {   
    }
    /// @result The user name. 
    [[nodiscard]] const std::string &getUser() const noexcept
    {
        return mUser;
    }
    /// @result The scope.
    [[nodiscard]] Claims::Scope getScope() const noexcept
    {
        return mScope;
    }
    /// @result The expiration time.
    [[nodiscard]] std::chrono::system_clock::time_point getExpirationTime() const noexcept
    {
        return mExpiresAt;
    }
    /// @result True indicates this is an administrator token.
    [[nodiscard]] static bool isAdministrator(const Claims &claims) noexcept
    {
        return claims.getScope() == Claims::Scope::Administrator;
    }

    [[nodiscard]] const_iterator begin() const { return mPermissions.begin(); }
    [[nodiscard]] const_iterator end() const { return mPermissions.end(); }
    [[nodiscard]] const_iterator cbegin() const { return mPermissions.cbegin(); }
    [[nodiscard]] const_iterator cend() const { return mPermissions.cend(); }

    ClaimsType::iterator end() {return mPermissions.end(); }
    
    
    ~Claims() = default; 
    Claims(const Claims &) = default;
    Claims(Claims &&) noexcept = default;
    Claims& operator=(const Claims &) = default;
    Claims& operator=(Claims &&) noexcept = default;
private:
    std::vector<std::pair<std::string, std::string>> mPermissions;
    std::string mUser;
    Scope mScope{Scope::User};
    std::chrono::system_clock::time_point mExpiresAt; 
};

}
#endif
