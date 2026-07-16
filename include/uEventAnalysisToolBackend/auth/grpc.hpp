#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_GRPC_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_GRPC_HPP
#include <expected>
#include <utility>
#include <grpcpp/server_context.h>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/jsonWebToken.hpp>
#include <uEventAnalysisToolBackend/auth/authNZ.hpp>

namespace UEventAnalysisToolBackend::Auth
{

/// @brief Authenticates a client with Bearer (JWT) credentials. 
/// @param[in] authNZ   The authenticator/authorizer.
/// @param[in] context  The server context with the user's JWT in the
///                     Bearer header field.
/// @param[in] logger   The logger to which we will record the details of
///                     this authentication attempt.
/// @result The claims or a ready-to-return UNAUTHENTICATED status. 
/// @note This is likely to be used by almost every gRPC.
[[nodiscard]] std::expected<JSONWebToken::Claims, grpc::Status>
    authenticateBearer(const AuthNZ &authNZ, const grpc::ServerContext &context,
                       spdlog::logger *logger);
/// @brief Authenticates a client with Basic (username and password)
///        credentials. 
/// @param[in] authNZ   The authenticator/authorizer.
/// @param[in] context  The server context with the user's name and password in
///                     the Basic header field.
/// @param[in] logger   The logger to which we will record the details of
///                     this authentication attempt.
/// @result The claims or a ready-to-return UNAUTHENTICATED status. 
/// @note This is primarily used by the Login gRPC's.
[[nodiscard]] std::expected<JSONWebToken::Claims, grpc::Status>
    authenticateBasic(const AuthNZ &authNZ, const grpc::ServerContext &context,
                      spdlog::logger *logger);
/// @brief Utility function to decode a base64 username and password - e.g.,
///           echo -n sam-i-am:openup231#c | base64 
///        produces
///           c2FtLWktYW06b3BlbnVwMjMxI2M=
/// @param[in] base64   The base64 encoded string
///                     (e.g., c2FtLWktYW06b3BlbnVwMjMxI2M=)
/// @result The user name and password.
/// @throws std::invalid_argument if the string is empty, there is no
///         ':' separating the username and password, or the user 
///         is empty.
[[nodiscard]] std::pair<std::string, std::string> decodeBase64(const std::string &base64); 
}
#endif
