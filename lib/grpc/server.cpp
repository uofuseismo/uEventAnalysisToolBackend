#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/support/time.h> //NOLINT
//#include <uEventAnalysisToolAPI/admin/v1/service.grpc.pb.h>
//#include <uEventAnalysisToolAPI/auth/v1/service.grpc.pb.h>
#include "uEventAnalysisToolBackend/auth/authNZ.hpp"
#include "uEventAnalysisToolBackend/grpc/server.hpp"
#include "uEventAnalysisToolBackend/grpc/grpcServerOptions.hpp"
#include "uEventAnalysisToolBackend/services/loginService.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

class Server::ServerImpl
{
public:
    /// Run during construction
    void createServices()
    {
        std::unique_ptr<grpc::Service> loginService
             = std::make_unique<UEventAnalysisToolBackend::Services::LoginService> (mAuthNZ, mLogger); 
        mServicesMap.insert(std::pair {"LoginService", std::move(loginService)});
    }

    void start()
    {
        grpc::ServerBuilder builder;
        // TODO add global rules like messages size limits etc.

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
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    std::shared_ptr<UEventAnalysisToolBackend::Auth::AuthNZ> mAuthNZ{nullptr};

    // N.B. Services must outlive mServer (RegisterService keeps only a raw
    //      pointer).  This is guaranteed by declaration order: mServicesMap is
    //      declared before mServer, so it is destroyed after it.
    //      DO NOT reorder this map and the server.
    std::map<std::string, std::unique_ptr<grpc::Service>> mServicesMap;
    std::unique_ptr<grpc::Server> mServer{nullptr};

    std::atomic<bool> mServerStarted{false};
};

/// Destructor
Server::~Server() = default;
