#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_VALIDATE_CLIENT_ACCESS_TOKEN_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_VALIDATE_CLIENT_ACCESS_TOKEN_HPP
#include <optional>
#include <string>
#include <grpcpp/server_context.h>

namespace UEventAnalysisToolBackend::GRPC
{
/// @param[in] context      The gRPC server context.
/// @param[in] accessToken  The access token.
/// @result True indicates the client passed a valid access token
///         in the x-custom-auth-token field.
[[nodiscard]] bool validateClientAccessToken(
    const grpc::CallbackServerContext *context,
    const std::string &accessToken);

/// @param[in] context      The gRPC server context.
/// @param[in] accessToken  The access token.
/// @result True indicates the client passed a valid access token
///         in the x-custom-auth-token field.
/// @note In this variant if the access token is null then it is
///       understood that this route is not configured to use an
///       access token and this will result in true.
[[nodiscard]] bool validateClientAccessToken(
    const grpc::CallbackServerContext *context,
    const std::optional<std::string> &accessToken);

}
#endif
