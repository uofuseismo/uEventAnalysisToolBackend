#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_TO_REQUEST_IDENTIFIER
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_TO_REQUEST_IDENTIFIER
#include <string>
#include <grpcpp/server_context.h>

namespace UEventAnalysisToolBackend::GRPC
{
[[nodiscard]] std::string toRequestIdentifier(const grpc::CallbackServerContext &context);
}
#endif
