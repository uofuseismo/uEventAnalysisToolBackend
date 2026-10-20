#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_PASSWORD_POLICY_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_PASSWORD_POLICY_HPP
#include <cstddef>
#include <filesystem>
#include <memory>
#include <utility>

namespace UEventAnalysisToolBackend::Auth::Password
{

/// @class PasswordPolicy passwordPolicy.hpp
/// @brief Sets the user password policy.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class PasswordPolicy
{
public:
    /// @brief Constructor.
    PasswordPolicy();
    /// @brief Copy constructor.
    PasswordPolicy(const PasswordPolicy &policy);
    /// @brief Move constructor.
    PasswordPolicy(PasswordPolicy &&policy) noexcept;

    /// @brief Defines the shortest acceptable password in a password change.
    /// @param[in] minimumLength  The minimum password length.
    /// @throws std::invalid_argument if minimum length is not positive
    ///         or the maximum length is not larger than the minimum length.
    void setMinimumAndMaximumLength(std::pair<int, int> &minimumLength);
    /// @result The minimum and maximum password length.
    /// @note By default this is 12 and 64. 
    [[nodiscard]] int getMinimumAndMaximumLength() const noexcept;

    /// @brief Requires the password has at least one number.
    void enableRequiresNumber() noexcept;
    /// @brief Does not require the password have a number.
    void disableRequiresNumber() noexcept;
    /// @result True indicates the password requires a number.
    /// @note By default this is true. 
    [[nodiscard]] bool requiresNumber() const noexcept;

    /// @brief Requires the password has at least one special character.
    ///        A special character is something other than a letter or
    ///        digit.
    void enableRequiresSpecialCharacter() noexcept;
    /// @brief Does not require the password have a special character.
    void disableRequiresSpecialCharacter() noexcept;
    /// @result True indicates the password requires a special character.
    /// @note By default this is false.
    [[nodiscard]] bool requiresSpecialCharacter() const noexcept;

    /// @brief Requires the new password must be different from the old password.
    void enableNewAndOldPasswordMustDiffer() noexcept;
    /// @brief Allows the new password to match the old password.
    void disableNewAndOldPasswordMustDiffer() noexcept;  
    /// @result True indicates that the new and old password must be different.
    /// @note By default this is true.
    [[nodiscard]] bool newAndOldPasswordMustDiffer() const noexcept; 

    /// @brief Creates the user password policy from an initialization file.
    /// @throws std::invalid_argument if the ini file path does not exist.
    [[nodiscard]] static PasswordPolicy fromInitializationFile(const std::filesystem::path &path, const std::string &section = "UserPasswordPolicy");

    /// @brief Converts the parameters to a message.
    /// @param[in] identifier  The request identifier.
    /// @note This is defined for UEventAnalysisToolAPI::Auth::V1::PasswordRequirements
    template<typename U> [[nodiscard]] U toMessage() const noexcept;

    /// @brief Destructor.
    ~PasswordPolicy();
    /// @brief Copy assignment.
    PasswordPolicy& operator=(const PasswordPolicy &policy);
    /// @brief Move assignemnt.
    PasswordPolicy& operator=(PasswordPolicy &&policy) noexcept;
private:
    class PasswordPolicyImpl;
    std::unique_ptr<PasswordPolicyImpl> pImpl;
};

}
#endif
