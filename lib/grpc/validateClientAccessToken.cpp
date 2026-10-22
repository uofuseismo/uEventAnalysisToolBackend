#include <optional>
#include <string>
#include <grpcpp/server_context.h>
#include "uEventAnalysisToolBackend/grpc/validateClientAccessToken.hpp"

/// @result True indicates the client passed a valid access token.
bool UEventAnalysisToolBackend::GRPC::validateClientAccessToken(
    const grpc::CallbackServerContext *context,
    const std::string &accessToken)
{
    if (accessToken.empty()) { return true; }
    for (const auto &item : context->client_metadata())
    {   
        if (item.first == "x-custom-auth-token")
        {
            if (item.second == accessToken) { return true; }
        }
    }   
    return false;
}

bool UEventAnalysisToolBackend::GRPC::validateClientAccessToken(
    const grpc::CallbackServerContext *context,
    const std::optional<std::string> &accessToken)
{
    if (accessToken != std::nullopt)
    {
        return validateClientAccessToken(context, *accessToken);
    }
    return true;
}

