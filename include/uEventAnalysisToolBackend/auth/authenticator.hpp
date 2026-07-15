#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_AUTHENTICATOR_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_AUTHENTICATOR_HPP
#include <string>
#include <utility>
namespace UEventAnalysisToolBackend::Auth
{
/// @class IAuthenticator
/// @brief The abstract base class to authenticate a user.
/// @name Ben Baker (University of Utah) distributed under the MIT NO AI
///       license.
class IAuthenticator
{
public:
    /// @brief Defines the result of authentication.
    enum class Result
    {
        Authenticated,      /*!< User was successfully authenticated.  This is like a 200 return code. */
        InvalidCredentials, /*!< User was rejeceted because of invalid credentials.  For example,
                                 if using Basic authentication the user name or password could be
                                wrong or if using bearer then the token could be expired. */
        ServerError         /*!< A backend service raised an error.  This is like a 500 return code. */
    };
public:
    IAuthenticator();

    /// @brief Performs basic authentication.
    /// @param[in] userNameAndPassword  userNameAndPassword.first is the user
    ////                                and userNameAndPassword.second is the
    ///                                 password.
    /// @result The result of the authentication.
    [[nodiscard]] virtual Result authenticateBasic(const std::pair<std::string, std::string> &userNameAndPassword);
    /// @brief Performs bearer authentication of a JWT.
    /// @param[in] jwt  The JSON Web Token.
    [[nodiscard]] virtual Result authenticateBearer(const std::string &jwt);
    /// @brief Destructor
    virtual ~IAuthenticator();
};
}
#endif
