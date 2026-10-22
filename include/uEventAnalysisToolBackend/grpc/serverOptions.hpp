#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_SERVER_OPTIONS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_SERVER_OPTIONS_HPP
#include <cstdint>
#include <string>
#include <memory>
#include <filesystem>
#include <optional>
namespace UEventAnalysisToolBackend::GRPC
{
 class GRPCServerOptions;
}
namespace UEventAnalysisToolBackend::GRPC
{
/// @class ServerOptions serverOptions.hpp
/// @brief Manages the options for the gRPC server (the thing the frontend
///        will interact with).
/// @copyright Ben Baker (University of Utah) distributed under the MIT 
///            NO AI license.
class ServerOptions
{
public:
    /// @brief Constructor
    ServerOptions();
    /// @brief Copy constructor.
    ServerOptions(const ServerOptions &options);
    /// @brief Move constructor.
    ServerOptions(ServerOptions &&options) noexcept;

    /// @brief Sets the gRPC server options.
    void setGRPCOptions(const GRPCServerOptions &options);
    /// @result The gRPC server options.
    /// @throws std::runtime_error if \c hasGRPCOptions is false.
    [[nodiscard]] GRPCServerOptions getGRPCOptions() const;
    /// @result True indicates that the gRPC server options were set.
    [[nodiscard]] bool hasGRPCOptions() const noexcept;

    /// @brief Destructor
    ~ServerOptions();
    /// @brief Copy assignment.
    ServerOptions& operator=(const ServerOptions &options);
    /// @brief Move assignment.
    ServerOptions& operator=(ServerOptions &&options) noexcept;
private:
    class ServerOptionsImpl;
    std::unique_ptr<ServerOptionsImpl> pImpl;
};
}
#endif
