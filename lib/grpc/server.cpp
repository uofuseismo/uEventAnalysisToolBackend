#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#ifndef NDEBUG
#include <cassert>
#endif
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/support/interceptor.h>
#include <grpcpp/support/server_interceptor.h>
//#include <grpcpp/support/string_ref.h>
#include <grpcpp/support/time.h> //NOLINT
//#include <uEventAnalysisToolAPI/admin/v1/service.grpc.pb.h>
//#include <uEventAnalysisToolAPI/auth/v1/service.grpc.pb.h>
#include "uEventAnalysisToolBackend/auth/authNZ.hpp"
#include "uEventAnalysisToolBackend/grpc/server.hpp"
#include "uEventAnalysisToolBackend/grpc/serverOptions.hpp"
#include "uEventAnalysisToolBackend/grpc/grpcServerOptions.hpp"
#include "uEventAnalysisToolBackend/grpc/requestIdentifierInterceptor.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

namespace
{

/*
[[nodiscard]] bool isAcceptable(const grpc::string_ref &metadata)
{
    constexpr size_t maximumLength{128};
    // Empty
    if (metadata.empty()){return false;}
    // Don't want to log really long identifiers
    if (metadata.size() > maximumLength){return false;}
    // Printable ASCII only: no tabs, newlines, or other control characters.
    auto printable
        = std::all_of(metadata.begin(), metadata.end(),
                      [](const auto c)
                      {
                          return c >= 0x20 && c <= 0x7E;
                      });
    if (!printable){return false;}
    // And not all blanks
    auto hasContent
        = std::any_of(metadata.begin(), metadata.end(),
                      [](const auto c)
                      {
                         return c != ' ';
                      });
    return hasContent; 
}

[[nodiscard]] std::string makeIdentifier()
{
    thread_local boost::uuids::time_generator_v7 generator;
    return boost::uuids::to_string(generator());
}

class RequestIdentifierInterceptor : public grpc::experimental::Interceptor
{
public:
    void Intercept(grpc::experimental::InterceptorBatchMethods *methods) override
    {
        using grpc::experimental::InterceptionHookPoints;
        if (methods->QueryInterceptionHookPoint(
            InterceptionHookPoints::POST_RECV_INITIAL_METADATA))
        {
            auto *metadata = methods->GetRecvInitialMetadata();
#ifndef NDEBUG
            assert(metadata != nullptr); // Guaranteed by grpc by this point 
#endif
            auto idx = metadata->find("x-request-id");
            // Was it set?
            if (idx != metadata->end() && ::isAcceptable(idx->second))
            {
                mIdentifier.assign(idx->second.data(), idx->second.size());
            }
            else
            {
                if (idx != metadata->end()){metadata->erase(idx);}
                mIdentifier = ::makeIdentifier();
                // string_refs into literal and into mIdentifier which lives as
                // long as the RPC.  Do not touch mIdentifier after this.
                metadata->emplace("x-request-id", mIdentifier);
            }
        }
        if (methods->QueryInterceptionHookPoint(
            InterceptionHookPoints::PRE_SEND_INITIAL_METADATA))
        {
            methods->GetSendInitialMetadata()->emplace("x-request-id", mIdentifier);
        }
        methods->Proceed();
    }
private:
    std::string mIdentifier;
};
*/

class RequestIdentifierInterceptorFactory :
    public grpc::experimental::ServerInterceptorFactoryInterface
{
public:
    explicit RequestIdentifierInterceptorFactory
    (
        const size_t maximumRequestIdentifierSize
    ) :
        grpc::experimental::ServerInterceptorFactoryInterface {},
        mMaximumRequestIdentifierSize{maximumRequestIdentifierSize}
    {
        if (mMaximumRequestIdentifierSize < 1 ||
            mMaximumRequestIdentifierSize > 8192)
        {
            throw std::invalid_argument(
               "Max request identifier must be between 1 and 8192 bytes");
        }
    }

    grpc::experimental::Interceptor *
    CreateServerInterceptor(grpc::experimental::ServerRpcInfo *) override
    {
        return new RequestIdentifierInterceptor(
            mMaximumRequestIdentifierSize); // gRPC takes ownership
    }
    size_t mMaximumRequestIdentifierSize{128};
};

}

class Server::ServerImpl
{
public:
    ServerImpl
    (
        const ServerOptions &serverOptions,
        std::map<std::string, std::unique_ptr<grpc::Service>> &&servicesMap,
        std::shared_ptr<spdlog::logger> logger
    ) :
        mServerOptions(serverOptions),
        mLogger(std::move(logger)),
        mServicesMap(std::move(servicesMap))
    {
        if (!mServerOptions.hasGRPCOptions())
        {
            throw std::invalid_argument("gRPC server options not set");
        }
        if (mServicesMap.empty())
        {
            throw std::invalid_argument("No services");
        }
        for (auto &service : mServicesMap)
        {
            if (service.second == nullptr)
            {
                throw std::invalid_argument(service.first + " is null");
            }
        }
    }

    /// Run during construction
    void start()
    {
        auto grpcOptions = mServerOptions.getGRPCOptions();
        // Interceptors
        std::vector
        <
            std::unique_ptr
            <
                grpc::experimental::ServerInterceptorFactoryInterface
            >
        > creators;
        creators.push_back(
             std::make_unique<::RequestIdentifierInterceptorFactory>
                 (grpcOptions.getMaximumRequestIdentifierSizeInBytes())
        );

        grpc::ServerBuilder builder;
        builder.experimental().SetInterceptorCreators(std::move(creators));
        // TODO add global rules like messages size limits etc and GRPC_ARG_MAX_METADATA_SIZE.

        // TODO add listening port and address and load in the certs

        // Register before start
        for (auto &service : mServicesMap)
        {
            SPDLOG_LOGGER_DEBUG(mLogger, "Registering {}", service.first);
            builder.RegisterService(service.second.get());
        }
        mServer = builder.BuildAndStart();
        if (mServer == nullptr)
        {
            throw std::runtime_error("Failed to start server");
        }
        mServerStarted.store(true);
        mServer->Wait();
        mServerStarted.store(false);
    } 

    void stop()
    {
        if (mServer && mServerStarted.exchange(false))
        {
            SPDLOG_LOGGER_INFO(mLogger, "Shutting down service");
            constexpr int64_t timeOutSeconds{1};
            constexpr int64_t timeOutNanoSeconds{0};
            const gpr_timespec deadline // NOLINT
            {
                timeOutSeconds,
                timeOutNanoSeconds,
                GPR_TIMESPAN // NOLINT
            };
            mServer->Shutdown(deadline);
            SPDLOG_LOGGER_INFO(mLogger, "Service shut down");
            mServer = nullptr;
        }
    }

    ~ServerImpl()
    {
        stop();
    }
//private:
    ServerOptions mServerOptions;    
    // N.B. Services must outlive mServer (RegisterService keeps only a raw
    //      pointer).  This is guaranteed by declaration order: mServicesMap is
    //      declared before mServer, so it is destroyed after it.
    //      DO NOT reorder this map and the server.
    std::map<std::string, std::unique_ptr<grpc::Service>> mServicesMap;
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    // After mServicesMap
    std::unique_ptr<grpc::Server> mServer{nullptr};
    std::atomic<bool> mServerStarted{false};
};

/// Constructor
Server::Server(
        const ServerOptions &serverOptions,
        std::map<std::string, std::unique_ptr<grpc::Service>> &&servicesMap,
        std::shared_ptr<spdlog::logger> logger
    ) :
    pImpl(std::make_unique<ServerImpl> (serverOptions,
                                        std::move(servicesMap),
                                        std::move(logger)))
{
}

/// Destructor
Server::~Server() = default;
