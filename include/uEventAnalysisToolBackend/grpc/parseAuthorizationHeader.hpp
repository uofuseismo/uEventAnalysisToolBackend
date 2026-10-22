#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_PARSE_AUTHORIZATION_HEADER_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_PARSE_AUTHORIZATION_HEADER_HPP
#include <expected>
#include <string>
#include <grpcpp/support/status.h>

namespace UEventAnalysisToolBackend::GRPC
{

/// @brief Extracts the user name and password from the grpc authorization
///        header field.  This search es for a basic credential.
[[nodiscard]]
std::expected
<
   std::pair<std::string, std::string>,
   grpc::Status
> 
authorizationHeaderToUserNameAndPassword(const grpc::string_ref &grpcHeader);

/// @brief Extracts the JWT from the grpc Authorization header field.
///        This searches for a bearer credential.
[[nodiscard]]
std::expected
<
   std::string,
   grpc::Status
> 
authorizationHeaderToToken(const grpc::string_ref &grpcHeader);

 
}
#endif
