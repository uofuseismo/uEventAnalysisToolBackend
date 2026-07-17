#include <exception>
#include <expected>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#ifndef NDEBUG
#include <cassert>
#endif
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include <boost/beast/core/detail/base64.hpp>
#include "uEventAnalysisToolBackend/auth/grpc.hpp"
#include "uEventAnalysisToolBackend/auth/authNZ.hpp"
#include "uEventAnalysisToolBackend/auth/jsonWebToken.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"

using namespace UEventAnalysisToolBackend::Auth;

std::expected<JSONWebToken::Claims, grpc::Status>
UEventAnalysisToolBackend::Auth::authenticateBearer(
    const AuthNZ &authNZ,
    const grpc::CallbackServerContext &context,
    spdlog::logger *logger)
{
    const auto &metadata = context.client_metadata();
    auto idx = metadata.find("Bearer");
    if (idx == metadata.end())
    {
        if (logger)
        {
            SPDLOG_LOGGER_WARN(logger,
                               "{} did not provide Bearer creds",
                               context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::UNAUTHENTICATED,
            "Bearer credential not set in header"};
        return std::unexpected(std::move(status));
    }
    const std::string jwt{idx->second.data(), idx->second.length()}; 
    if (jwt.empty())
    {
        if (logger)
        {
            SPDLOG_LOGGER_WARN(logger,
                               "{} provided empty JWT",
                               context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::UNAUTHENTICATED,
            "Bearer credential is empty"};
        return std::unexpected(std::move(status));
    }
    // Throws - this is a server error and should return INTERNAL
    try
    {
        auto [authResult, optionalClaims] = authNZ.authenticate(jwt);
        if (authResult == IAuthenticator::Result::Authenticated)
        {
            // You should have claims at this point - even if it is an empty
            // vector
            if (optionalClaims != std::nullopt)
            {
                if (logger)
                {
                    SPDLOG_LOGGER_INFO(logger,
                       "{} ({}) JWT authenticated",
                       optionalClaims->user, context.peer());
                }
                return *optionalClaims;
            }
            if (logger)
            {
                SPDLOG_LOGGER_ERROR(logger,
                   "Null claims returned for {}", context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::INTERNAL,
                "Internal error - contact maintainer"};
            return std::unexpected(std::move(status));
        }
        else if (authResult == IAuthenticator::Result::InvalidCredentials)
        {
            if (logger)
            {
                SPDLOG_LOGGER_WARN(logger,
                   "{} provided an invalid JWT", context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::UNAUTHENTICATED,
                "JWT is invalid - you can attempt to login again"};
            return std::unexpected(std::move(status));
        }
        else if (authResult == IAuthenticator::Result::ServerError)
        {
            if (logger)
            {
                SPDLOG_LOGGER_ERROR(logger,
                    "Rejecting {} because of server error",
                    context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::INTERNAL,
                "Internal error - try again then contact maintainer"};
            return std::unexpected(std::move(status));
        }
        if (logger)
        {
            SPDLOG_LOGGER_ERROR(logger,
                "Unhandled logic when processing {}",
                 context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::INTERNAL,
            "Internal error - contact maintainer"};
        return std::unexpected(std::move(status));
    }
    catch (const std::exception &e)
    {
        if (logger)
        {
            SPDLOG_LOGGER_ERROR(logger,
                "Rejecting {} because server error {}",
                 context.peer(), e.what());
        }
        grpc::Status status{
            grpc::StatusCode::INTERNAL,
            "Internal error - contact maintainer"};
        return std::unexpected(std::move(status));
    }
}

std::expected<JSONWebToken::Claims, grpc::Status>
UEventAnalysisToolBackend::Auth::authenticateBasic(
    const AuthNZ &authNZ,
    const grpc::CallbackServerContext &context,
    spdlog::logger *logger)
{
    const auto &metadata = context.client_metadata();
    auto idx = metadata.find("Basic");
    if (idx == metadata.end()) 
    {
        if (logger)
        {
            SPDLOG_LOGGER_WARN(logger,
                               "{} did not provide Basic creds",
                               context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::UNAUTHENTICATED,
            "Basic credential not set in header"};
        return std::unexpected(std::move(status));
    }
    const std::string base64{idx->second.data(), idx->second.length()};
    if (base64.empty())
    {
        if (logger)
        {
            SPDLOG_LOGGER_WARN(logger,
                               "{} provided empty credentials",
                               context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::UNAUTHENTICATED,
            "Basic credential is empty"};
        return std::unexpected(std::move(status));
    }
    // Parse the base64 to a user and password 
    std::pair<std::string, std::string> userNameAndPassword;
    try
    {
        userNameAndPassword = decodeBase64(base64);    
    }
    catch (const std::exception &e)
    {
        if (logger)
        {
            SPDLOG_LOGGER_WARN(logger,
               "Rejecting {} - provided malformed credentials ({})",
               context.peer(), e.what());
        }
        grpc::Status status{
            grpc::StatusCode::INVALID_ARGUMENT,
            "Basic credentials are malformed"};
        return std::unexpected(std::move(status));
    }
    const auto &user = userNameAndPassword.first;
    const auto &password = userNameAndPassword.second;
    // Finally validate
    try
    {
        auto [authResult, optionalClaims]
            = authNZ.authenticate(std::pair {user, password});
        if (authResult == IAuthenticator::Result::Authenticated)
        {
            // You should have claims at this point - even if it is an empty
            // vector
            if (optionalClaims != std::nullopt)
            {
                if (logger)
                {
                    SPDLOG_LOGGER_INFO(logger,
                        "{} ({}) basic credentials authenticated",
                        optionalClaims->user, context.peer());
                }
                return *optionalClaims;
            }
            if (logger)
            {
                SPDLOG_LOGGER_ERROR(logger,
                   "Null claims returned for {}", context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::INTERNAL,
                "Internal error - contact maintainer"};
            return std::unexpected(std::move(status));
        }
        else if (authResult == IAuthenticator::Result::InvalidCredentials)
        {
            if (logger)
            {
                SPDLOG_LOGGER_WARN(logger,
                    "{} provided invalid credentials",
                    context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::UNAUTHENTICATED,
                "The credentials are invalid"};
            return std::unexpected(std::move(status));
        }
        else if (authResult == IAuthenticator::Result::ServerError)
        {
            if (logger)
            {
                SPDLOG_LOGGER_ERROR(logger,
                   "Rejecting {} ({}) because of server error",
                   user, context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::INTERNAL,
                "Internal error - try again then contact maintainer"};
            return std::unexpected(std::move(status));
        }
        if (logger)
        {
            SPDLOG_LOGGER_ERROR(logger,
                "Unhandled logic when processing {} ({})",
                user, context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::INTERNAL,
            "Internal error - contact maintainer"};
        return std::unexpected(std::move(status));
    }
    catch (const std::exception &e)
    {
        if (logger)
        {
            SPDLOG_LOGGER_ERROR(logger,
                "Rejecting {} ({}) because server error {}",
                user, context.peer(), e.what());
        }
        grpc::Status status{
            grpc::StatusCode::INTERNAL,
            "Internal error - contact maintainer"};
        return std::unexpected(std::move(status));
    }
}

std::expected<std::string, grpc::Status>
UEventAnalysisToolBackend::Auth::loginBasic(
    const AuthNZ &authNZ,
    const grpc::CallbackServerContext &context,
    spdlog::logger *logger)
{
    const auto &metadata = context.client_metadata();
    auto idx = metadata.find("Basic");
    if (idx == metadata.end()) 
    {
        if (logger)
        {
            SPDLOG_LOGGER_WARN(logger,
                               "{} did not provide Basic creds",
                               context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::UNAUTHENTICATED,
            "Basic credential not set in header"};
        return std::unexpected(std::move(status));
    }
    const std::string base64{idx->second.data(), idx->second.length()};
    if (base64.empty())
    {
        if (logger)
        {
            SPDLOG_LOGGER_WARN(logger,
                               "{} provided empty credentials",
                               context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::UNAUTHENTICATED,
            "Basic credential is empty"};
        return std::unexpected(std::move(status));
    }
    // Parse the base64 to a user and password 
    std::pair<std::string, std::string> userNameAndPassword;
    try
    {
        userNameAndPassword = decodeBase64(base64);    
    }
    catch (const std::exception &e)
    {
        if (logger)
        {
            SPDLOG_LOGGER_WARN(logger,
               "Rejecting {} - provided malformed credentials ({})",
               context.peer(), e.what());
        }
        grpc::Status status{
            grpc::StatusCode::INVALID_ARGUMENT,
            "Basic credentials are malformed"};
        return std::unexpected(std::move(status));
    }
    const auto &user = userNameAndPassword.first;
    const auto &password = userNameAndPassword.second;
    // Finally validate
    try
    {
        auto [authResult, jwt] = authNZ.login(std::pair {user, password});
        if (authResult == IAuthenticator::Result::Authenticated)
        {
            // Send the JWT back
            if (!jwt.empty())
            {
                if (logger)
                {
                    SPDLOG_LOGGER_INFO(logger,
                        "{} ({}) basic credentials authenticated",
                        user, context.peer());
                }
                return jwt;
            }
            if (logger)
            {
                SPDLOG_LOGGER_ERROR(logger,
                   "Null JWT returned for {}", context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::INTERNAL,
                "Internal error - contact maintainer"};
            return std::unexpected(std::move(status));
        }
        else if (authResult == IAuthenticator::Result::InvalidCredentials)
        {
            if (logger)
            {
                SPDLOG_LOGGER_WARN(logger,
                    "{} provided invalid credentials",
                    context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::UNAUTHENTICATED,
                "The credentials are invalid"};
            return std::unexpected(std::move(status));
        }
        else if (authResult == IAuthenticator::Result::ServerError)
        {
            if (logger)
            {
                SPDLOG_LOGGER_ERROR(logger,
                   "Rejecting {} ({}) because of server error",
                   user, context.peer());
            }
            grpc::Status status{
                grpc::StatusCode::INTERNAL,
                "Internal error - try again then contact maintainer"};
            return std::unexpected(std::move(status));
        }
        if (logger)
        {
            SPDLOG_LOGGER_ERROR(logger,
                "Unhandled logic when processing {} ({})",
                user, context.peer());
        }
        grpc::Status status{
            grpc::StatusCode::INTERNAL,
            "Internal error - contact maintainer"};
        return std::unexpected(std::move(status));
    }
    catch (const std::exception &e)
    {
        if (logger)
        {
            SPDLOG_LOGGER_ERROR(logger,
                "Rejecting {} ({}) because server error {}",
                user, context.peer(), e.what());
        }
        grpc::Status status{
            grpc::StatusCode::INTERNAL,
            "Internal error - contact maintainer"};
        return std::unexpected(std::move(status));
    }
}


std::pair<std::string, std::string>
UEventAnalysisToolBackend::Auth::decodeBase64(const std::string &base64)
{
    if (base64.empty())
    {
        throw std::invalid_argument("base64 input string is empty");
    }
    // The workspace is an upper bound
    auto workspace
        = static_cast<int> 
          (boost::beast::detail::base64::decoded_size(base64.size()));
    std::vector<char> buffer(workspace + 1, '\0');
    auto [nOctets, nCharactersRead]
        = boost::beast::detail::base64::decode(buffer.data(),
                                               base64.c_str(),
                                               base64.size());
    // Trim out the null terminators and put in a string buffer
    std::string userNameAndPassword(buffer.data());
    // Find the first occurrence of an ":" - basically says
    // usernames can't have ":" in them.  Good safety tip. 
    auto colonIndex = userNameAndPassword.find_first_of(':');
    if (colonIndex == std::string::npos) 
    {
        throw std::invalid_argument(
           "base64 username and password malformed - no colon separator");
    }       
    if (colonIndex == 0)
    {
        throw std::invalid_argument("User name is empty");
    }
    // It looks like there is a carriage return - remove this
    if (userNameAndPassword.back() == '\0' ||
        userNameAndPassword.back() == '\n')
    {
        userNameAndPassword.pop_back();
    }
    auto userLength = colonIndex;
    auto user = userNameAndPassword.substr(0, userLength);
    // Could send is something like "user:" which would be an empty password.
    std::string password;
    if (colonIndex < userNameAndPassword.size() - 1)
    {
        password
            = userNameAndPassword.substr(colonIndex + 1);
    }
    return std::pair {user, password};
}
