#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_SERVER_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_SERVER_HPP
#include <memory>
#include <spdlog/logger.h>

namespace UEventAnalysisToolBackend::Auth
{
 class AuthNZ;
} 
namespace UEventAnalysisToolBackend::GRPC
{
 class ServerOptions;
}
namespace UEventAnalysisToolBackend::GRPC
{
/// @class Server server.hpp
/// @brief This is the server with which the frontend clients interacts.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class Server
{
public:
    Server(const ServerOptions &options,
           std::shared_ptr<UEventAnalysisToolBackend::Auth::AuthNZ> authNZ,
           std::shared_ptr<spdlog::logger> logger);


    /// @brief Destructor.
    ~Server();

    Server& operator=(const Server &) = delete;
    Server& operator=(Server &&) noexcept = delete;
    Server(const Server &) = delete;
    Server(Server &&) noexcept = delete;
private:
    class ServerImpl;
    std::unique_ptr<ServerImpl> pImpl;
};
}
#endif
