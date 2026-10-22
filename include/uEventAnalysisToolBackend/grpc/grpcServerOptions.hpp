#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_GRPC_SERVER_OPTIONS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_GRPC_SERVER_OPTIONS_HPP
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
namespace UEventAnalysisToolBackend::GRPC
{
/// @class GRPCServerOptions grpcServerOptions.hpp
/// @brief Manages the options for the gRPC server (the thing the frontend
///        will interact with).
/// @copyright Ben Baker (University of Utah) distributed under the MIT 
///            NO AI license.
class GRPCServerOptions
{
public:
    /// @brief Constructor
    GRPCServerOptions();

    /// @brief Sets the host name - e.g., localhost or machine.domain.com.
    void setHost(const std::string &host);
    /// @result The host name.
    /// @note By default this is localhost. 
    [[nodiscard]] std::string getHost() const noexcept;

    /// @brief Sets the port number.
    void setPort(uint16_t port);
    /// @result The port.
    /// @note By default this is 50000.
    [[nodiscard]] uint16_t getPort() const noexcept;

    /// @brief Sets the API access token.
    //void setAccessToken(const std::string &token);
    /// @result The access token.
    /// @note Access tokens can only be used by gRPC if the server
    ///       certificate is set.
    //[[nodiscard]] std::optional<std::string> getAccessToken() const noexcept;

    /// @brief Sets the server's certificate.  This is public - e.g.,
    ///        localhost.crt.
    void setServerCertificate(const std::string &certificate);
    /// @result The server certificate.
    /// @note The server key must also be set for gRPC to use this.
    /// @throws std::runtime_error if the server certificate was not set.
    [[nodiscard]] std::string getServerCertificate() const;
    /// @result True indicates the server certificate was set.
    [[nodiscard]] bool hasServerCertificate() const noexcept;

    /// @brief Sets the server's key.  This is private - e.g., localhost.key.
    void setServerKey(const std::string &key);
    /// @result The server key.
    /// @note The server certificate must also be set for gRPC to use this.
    /// @throws std::runtime_error if the server key was not set.
    [[nodiscard]] std::string getServerKey() const;
    /// @result True indicates the server key was set.
    [[nodiscard]] bool hasServerKey() const noexcept;

    /// @brief Sets the client certificate for a full key exchange.
    void setClientCertificate(const std::string &certificate);
    /// @result The client ceritificate.
    [[nodiscard]] std::optional<std::string> getClientCertificate() const noexcept;

    /// @brief Enables reflection.
    void enableReflection() noexcept;
    /// @brief Disables reflections.
    void disableReflection() noexcept;
    /// @result True indicates reflection is enabled.  
    /// @note By default this is false.
    [[nodiscard]] bool isReflectionEnabled() const noexcept;

    /// @brief Sets the maximum request message size in bytes.
    /// @throws std::invalid_argument if maxMessageSize is not positive.
    void setMaximumRequestMessageSizeInBytes(int maxMessageSize);
    /// @result The maximum request message size in bytes.
    /// @note By default this is 65536.
    [[nodiscard]] int getMaximumRequestMessageSizeInBytes() const noexcept;

    /// @brief Sets the maximum connection age.  After this amount of time
    ///        the connection is terminated.
    void setMaximumConnectionAge(const std::chrono::milliseconds &maxConnectionAge);
    /// @result The maximum connection age.
    /// @note By default this is 3 minutes.
    [[nodiscard]] std::chrono::milliseconds getMaximumConnectionAge() const noexcept;

    /// @brief After the maximum connection age is hit, this is the amount of
    ///        of time to wait for the RPC to finish.
    void setMaximumConnectionAgeGracePeriod(const std::chrono::milliseconds &maxGracePeriod);
    /// @result The maximum grace period for RPCs belonging to connections
    ///         that look stale.
    /// @note By default this is 2 seconds.
    [[nodiscard]] std::chrono::milliseconds getMaximumConnectionAgeGracePeriod() const noexcept;

    /// @brief Sets the maximum request identifier to be stored in 
    ///        x-request-id header field.  After this point the
    ///        x-request-id is considered invalid and overwritten
    ///        with a UID.
    /// @param[in] maxIdentifierSize  The max identifier size in bytes.
    /// @throws std::invalid_argument if this is not in the range [1, 8192].
    void setMaximumRequestIdentifierSizeInBytes(int maxIdentifierSize);
    /// @result The maximum request identifier size in bytes.
    /// @note By default this is 128.
    [[nodiscard]] int getMaximumRequestIdentifierSizeInBytes() const noexcept;

    /// @brief Destructor
    ~GRPCServerOptions();
    /// @brief Copy constructor.
    GRPCServerOptions(const GRPCServerOptions &options);
    /// @brief Move constructor.
    GRPCServerOptions(GRPCServerOptions &&options) noexcept;
    /// @brief Copy assignment.
    GRPCServerOptions& operator=(const GRPCServerOptions &options);
    /// @brief Move assignment.
    GRPCServerOptions& operator=(GRPCServerOptions &&options) noexcept;

    /// @brief Loads the GRPC server options from an initialization file.
    static GRPCServerOptions fromInitializationFile(
        const std::filesystem::path &iniFile,
        const std::string &section = "GRPCServer");

private:
    class GRPCServerOptionsImpl;
    std::unique_ptr<GRPCServerOptionsImpl> pImpl;
};
}
#endif
