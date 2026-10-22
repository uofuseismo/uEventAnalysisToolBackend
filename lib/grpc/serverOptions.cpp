#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include "uEventAnalysisToolBackend/grpc/serverOptions.hpp"
#include "uEventAnalysisToolBackend/grpc/grpcServerOptions.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

class ServerOptions::ServerOptionsImpl
{
public:
    GRPCServerOptions mGRPCServerOptions;
    bool mHasGRPCServerOptions{false};
};

/// Constructor
ServerOptions::ServerOptions() :
    pImpl(std::make_unique<ServerOptionsImpl> ())
{
}

/// Copy constructor
ServerOptions::ServerOptions(const ServerOptions &options)
{
    *this = options;
}

/// Move constructor
ServerOptions::ServerOptions(ServerOptions &&options) noexcept
{
    *this = std::move(options);
}

/// Copy assignment
ServerOptions& ServerOptions::operator=(const ServerOptions &options)
{
    if (&options == this){return *this;}
    pImpl = std::make_unique<ServerOptionsImpl> (*options.pImpl);
    return *this; 
}

/// Move assignment
ServerOptions& ServerOptions::operator=(ServerOptions &&options) noexcept
{
    if (&options == this){return *this;}
    pImpl = std::move(options.pImpl);
    return *this;
}

/// Destructor
ServerOptions::~ServerOptions() = default;

/// gRPC server options
void ServerOptions::setGRPCOptions(
    const GRPCServerOptions &options)
{
    // Sort out some inconsistencies with certs and keys, etc.
    if ( options.hasServerCertificate() &&
        !options.hasServerKey())
    {
        throw std::invalid_argument(
            "Cannot use server certificate without server key");
    }
    if (!options.hasServerCertificate() &&
         options.hasServerKey())
    {
        throw std::invalid_argument(
           "Cannot use server key without server certificate");
    }
    if (!options.hasServerCertificate() && 
        !options.hasServerKey())
    {
        if (options.getClientCertificate() != std::nullopt)
        {
            throw std::invalid_argument(
        "Need server certificate and key to use a client certificate for mTLS");
        }
    }
    pImpl->mGRPCServerOptions = options;
    pImpl->mHasGRPCServerOptions = true;
}

GRPCServerOptions ServerOptions::getGRPCOptions() const
{
    if (!hasGRPCOptions())
    {
        throw std::runtime_error("gRPC server options not set");
    }
    return pImpl->mGRPCServerOptions;
}

bool ServerOptions::hasGRPCOptions() const noexcept
{
    return pImpl->mHasGRPCServerOptions;
}
