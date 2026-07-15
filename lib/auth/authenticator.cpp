#include "uEventAnalysisToolBackend/auth/authenticator.hpp"

using namespace UEventAnalysisToolBackend::Auth;

IAuthenticator::IAuthenticator() = default;

/// Destructor
IAuthenticator::~IAuthenticator() = default;

/// Default implementations
IAuthenticator::Result IAuthenticator::authenticateBasic(
    const std::pair<std::string, std::string> &)
{
    return IAuthenticator::Result::ServerError;
}

IAuthenticator::Result IAuthenticator::authenticateBearer(
    const std::string &)
{
    return IAuthenticator::Result::ServerError;
}

