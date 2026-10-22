#include <string>
#include <grpcpp/server_context.h>
#include "uEventAnalysisToolBackend/grpc/toRequestIdentifier.hpp"

std::string
UEventAnalysisToolBackend::GRPC::toRequestIdentifier(
    const grpc::CallbackServerContext &context)
{
    // N.B. Our interceptor ensures this field is defined.
    const auto requestIdentifierIndex
         = context.client_metadata().find("x-request-id");
    std::string requestIdentifier
    {
        requestIdentifierIndex->second.data(),
        requestIdentifierIndex->second.size()
    };
    requestIdentifier.append(" [").append(context.peer()).append("]");
    return requestIdentifier;
}
