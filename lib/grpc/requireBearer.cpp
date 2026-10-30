#include <expected>
#include <utility>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include "uEventAnalysisToolBackend/grpc/requireBearer.hpp"
#include "uEventAnalysisToolBackend/auth/administratorTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"

namespace UAuth = UEventAnalysisToolBackend::Auth;
namespace UGRPC = UEventAnalysisToolBackend::GRPC;


std::expected<UAuth::Claims, grpc::Status>
UGRPC::requireBearer(const grpc::CallbackServerContext &context,
                     const UAuth::AdministratorTokenVerifier &verifier)
{
    // Extract the session token from Bearer
    auto bearerField = context.client_metadata().find("authorization");
    if (bearerField == context.client_metadata().end())
    {
        return std::unexpected(grpc::Status
                  {grpc::StatusCode::UNAUTHENTICATED,
                   "Admin bearer token required"});
    }
    auto token
        = UGRPC::authorizationHeaderToToken(bearerField->second);
    if (!token){return std::unexpected(token.error());}
    auto [result, claims] = verifier.verify(*token);
    if (result == UAuth::IAuthenticator::Result::Authenticated && claims)
    {
        return std::move(*claims);
    }
    if (result == UAuth::IAuthenticator::Result::ServerError)
    {
        return std::unexpected(grpc::Status{grpc::StatusCode::INTERNAL,
                                            "Internal error"});
    }
    return std::unexpected(grpc::Status{grpc::StatusCode::UNAUTHENTICATED,
                                        "Invalid or expired token"});
}

std::expected<UAuth::Claims, grpc::Status>
UGRPC::requireBearer(const grpc::CallbackServerContext &context,
                     const UAuth::UserTokenVerifier &verifier)
{
    // Extract the session token from Bearer
    auto bearerField = context.client_metadata().find("authorization");
    if (bearerField == context.client_metadata().end())
    {   
        return std::unexpected(grpc::Status
                  {grpc::StatusCode::UNAUTHENTICATED,
                   "User bearer token required"});
    }   
    auto token
        = UGRPC::authorizationHeaderToToken(bearerField->second);
    if (!token){return std::unexpected(token.error());}
    auto [result, claims] = verifier.verify(*token);
    if (result == UAuth::IAuthenticator::Result::Authenticated && claims)
    {   
        return std::move(*claims);
    }   
    if (result == UAuth::IAuthenticator::Result::ServerError)
    {   
        return std::unexpected(grpc::Status{grpc::StatusCode::INTERNAL,
                                            "Internal error"});
    }   
    return std::unexpected(grpc::Status{grpc::StatusCode::UNAUTHENTICATED,
                                        "Invalid or expired token"});
}

