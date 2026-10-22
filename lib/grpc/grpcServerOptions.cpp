#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "uEventAnalysisToolBackend/grpc/grpcServerOptions.hpp"
#include "secretFile.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

class GRPCServerOptions::GRPCServerOptionsImpl
{
public:
    std::string mHost{"localhost"};
    std::string mServerCertificate;
    std::string mServerKey;
    std::optional<std::string> mClientCertificate{std::nullopt};
    std::optional<std::string> mAccessToken{std::nullopt};
    int mMaximumRequestMessageSizeInBytes{65536};
    std::chrono::milliseconds mMaximumConnectionAge{std::chrono::seconds {180}};
    std::chrono::milliseconds mMaximumGracePeriod{std::chrono::seconds{2}};
    int mMaximumRequestIdentifierSize{128};
    uint16_t mPort{50000};
    bool mHaveServerCertificate{false}; 
    bool mHaveServerKey{false};
    bool mReflectionEnabled{false};
};

// Constructor
GRPCServerOptions::GRPCServerOptions() :
    pImpl(std::make_unique<GRPCServerOptionsImpl> ())
{
}

/// Copy constructor
GRPCServerOptions::GRPCServerOptions(const GRPCServerOptions &options)
{
    *this = options;
}

/// Move constructor
GRPCServerOptions::GRPCServerOptions(GRPCServerOptions &&options) noexcept
{
    *this = std::move(options);
}

/// Copy assignment
GRPCServerOptions&
GRPCServerOptions::operator=(const GRPCServerOptions &options)
{
    if (&options == this){return *this;}
    pImpl = std::make_unique<GRPCServerOptionsImpl> (*options.pImpl);
    return *this;
}

/// Move assignment
GRPCServerOptions&
GRPCServerOptions::operator=(GRPCServerOptions &&options) noexcept
{
    if (&options == this){return *this;}
    pImpl = std::move(options.pImpl);
    return *this;
}

/// Destructor
GRPCServerOptions::~GRPCServerOptions() = default;

/// Host
void GRPCServerOptions::setHost(const std::string &hostIn)
{
    auto host = hostIn;
    host.erase(
       std::remove_if(host.begin(), host.end(),
                      [](unsigned char c)
                      {
                         return std::isspace(c);
                      }),
       host.end());
    if (host.empty())
    {
        throw std::invalid_argument("Host is empty");
    }
    pImpl->mHost = host;
}

std::string GRPCServerOptions::getHost() const noexcept
{
    return pImpl->mHost;
}

/*
std::string UDataPacketService::makeAddress(const GRPCServerOptions &options)
{
    return options.getHost() + ":" + std::to_string(options.getPort());
}
*/

/// Port
void GRPCServerOptions::setPort(const uint16_t port)
{
    if (port < 1)
    {
        throw std::invalid_argument("Port must be positive");
    }
    pImpl->mPort = port;
}

uint16_t GRPCServerOptions::getPort() const noexcept
{
    return pImpl->mPort;
}

/// Server cert
void GRPCServerOptions::setServerCertificate(const std::string &cert)
{
    if (cert.empty())
    {
        throw std::invalid_argument("Server certificate is empty");
    }
    pImpl->mHaveServerCertificate = true;
    pImpl->mServerCertificate = cert;
}

std::string GRPCServerOptions::getServerCertificate() const
{
    if (!hasServerCertificate())
    {
        throw std::runtime_error("Server certificate not set");
    }
    return pImpl->mServerCertificate;
}

bool GRPCServerOptions::hasServerCertificate() const noexcept
{
    return pImpl->mHaveServerCertificate;
}

void GRPCServerOptions::setServerKey(const std::string &key)
{
    if (key.empty())
    {
        throw std::invalid_argument("Server key is empty");
    }
    pImpl->mHaveServerKey = true;
    pImpl->mServerKey = key;
}

std::string GRPCServerOptions::getServerKey() const
{
    if (!hasServerKey())
    {
        throw std::runtime_error("Server key not set");
    }
    return pImpl->mServerKey;
}

bool GRPCServerOptions::hasServerKey() const noexcept
{
    return pImpl->mHaveServerKey;
}

/// Client cert
void GRPCServerOptions::setClientCertificate(const std::string &cert)
{
    if (cert.empty())
    {
        throw std::invalid_argument("Client certificate is empty");
    }
    pImpl->mClientCertificate = std::make_optional<std::string> (cert);
}

std::optional<std::string> 
    GRPCServerOptions::getClientCertificate() const noexcept
{
    return pImpl->mClientCertificate;
}

/// Reflection
void GRPCServerOptions::enableReflection() noexcept
{
    pImpl->mReflectionEnabled = true;
}

void GRPCServerOptions::disableReflection() noexcept
{
    pImpl->mReflectionEnabled = false;
}

bool GRPCServerOptions::isReflectionEnabled() const noexcept
{
    return pImpl->mReflectionEnabled;
}


/*
/// Access token
void GRPCServerOptions::setAccessToken(const std::string &token)
{
    if (token.empty()){throw std::invalid_argument("Token is empty");}
    pImpl->mAccessToken = std::make_optional<std::string> (token);
}

std::optional<std::string> GRPCServerOptions::getAccessToken() const noexcept
{
    return pImpl->mAccessToken;
}
*/

/// Maximum connection age
void GRPCServerOptions::setMaximumConnectionAge(
    const std::chrono::milliseconds &duration)
{
    if (duration.count() < 1)
    {   
        throw std::invalid_argument("Max connection duration must be positive");
    }   
    pImpl->mMaximumConnectionAge = duration;
}

std::chrono::milliseconds
GRPCServerOptions::getMaximumConnectionAge() const noexcept
{
    return pImpl->mMaximumConnectionAge;
}

/// Maximum grace period
void GRPCServerOptions::setMaximumConnectionAgeGracePeriod(
    const std::chrono::milliseconds &period)
{
    if (period.count() < 0)
    {
        throw std::invalid_argument("Grace period must be non-negative");
    }
    pImpl->mMaximumGracePeriod = period;
}

std::chrono::milliseconds
GRPCServerOptions::getMaximumConnectionAgeGracePeriod() const noexcept
{
    return pImpl->mMaximumGracePeriod;
}

/// Maximum request message
void GRPCServerOptions::setMaximumRequestMessageSizeInBytes(
    const int maxMessageSize)
{
    if (maxMessageSize < 1)
    {
        throw std::invalid_argument(
            "Max request message size must be positive");
    }
    pImpl->mMaximumRequestMessageSizeInBytes = maxMessageSize;
}

int GRPCServerOptions::getMaximumRequestMessageSizeInBytes() const noexcept
{
    return pImpl->mMaximumRequestMessageSizeInBytes;
}

/// Max request identifier size
void GRPCServerOptions::setMaximumRequestIdentifierSizeInBytes(
    const int maxIdentifierSize)
{
    if (maxIdentifierSize < 1 || maxIdentifierSize > 8192)
    {
        throw std::invalid_argument(
           "Max request identifier size must be in range [1,8192]");
    }
    pImpl->mMaximumRequestIdentifierSize = maxIdentifierSize;
}

int GRPCServerOptions::getMaximumRequestIdentifierSizeInBytes() const noexcept
{
    return pImpl->mMaximumRequestIdentifierSize;
}


namespace
{
template<typename T>
T getOrDefault(const boost::property_tree::ptree &tree,
               const std::string &key,
               const T &defaultValue)
{
    const auto text = tree.get_optional<std::string> (key);
    if (!text){return defaultValue;}          // Not in the file
    const auto value = tree.get_optional<T> (key);
    if (!value)                               // In the file but garbage
    {
        throw std::invalid_argument(key + " = " + *text
                                  + " is not a valid value");
    }
    return *value;
}
}


/// Read server options from a config file
GRPCServerOptions GRPCServerOptions::fromInitializationFile(
    const std::filesystem::path &iniFile,
    const std::string &sectionIn)
{   
    if (!std::filesystem::exists(iniFile))
    {   
        throw std::invalid_argument("Initialization file "
                                  + iniFile.string() + " does not exist");
    }
    GRPCServerOptions options;
    // Make sure section ends with . so we can find stuff
    auto section = sectionIn;
    if (!section.empty() && section.back() != '.'){section.append(".");}

    // Parse the initialization file
    boost::property_tree::ptree propertyTree;
    boost::property_tree::ini_parser::read_ini(iniFile, propertyTree);
        
    auto host
        = propertyTree.get<std::string> (section + "host",
                                         options.getHost());
    if (host.empty())
    {
        throw std::invalid_argument(section + "host is empty");
    }
    options.setHost(host);

    int port{50000};
    port = ::getOrDefault<int> (propertyTree,
                                section + "port",
                                static_cast<int> (port));
    if (port < 1 || port > std::numeric_limits<uint16_t>::max())
    {
        throw std::invalid_argument(section + "port is out of range [1,65535]");
    }
    options.setPort(port);

    auto serverKey
        = ::resolveSecret(propertyTree,
                          section + "serverKey",
                          section + "serverKeyFile");
    auto serverCertificate
        = ::resolveSecret(propertyTree,
                          section + "serverCertificate",
                          section + "serverCertificateFile");
    bool haveServerCerts{false};
    if (serverKey != std::nullopt && serverCertificate != std::nullopt)
    {   
        options.setServerKey(*serverKey);
        options.setServerCertificate(*serverCertificate);
        haveServerCerts = true;
    }   
    else if (serverKey != std::nullopt || serverCertificate != std::nullopt)
    {   
        throw std::invalid_argument(
           "Server key and certificate must both be set");
    }

    auto enableReflection
         = ::getOrDefault<bool> (propertyTree,
                                 section + "enableReflection",
                                 false);
    options.disableReflection();
    if (enableReflection){options.enableReflection();}

    auto maximumRequestMessageSize
        = ::getOrDefault<int> (propertyTree,
                               section + "maximumRequestMessageSizeInBytes",
                               options.getMaximumRequestMessageSizeInBytes());
    options.setMaximumRequestMessageSizeInBytes(maximumRequestMessageSize);

    auto maximumRequestIdentifierSize
       = ::getOrDefault<int> (propertyTree,
                              section + "maximumRequestIdentifierSizeInBytes",
                              options.getMaximumRequestIdentifierSizeInBytes());
    options.setMaximumRequestIdentifierSizeInBytes(
        maximumRequestIdentifierSize);

    int maxConnectionAgeMilliS{
       static_cast<int> (options.getMaximumConnectionAge().count())};
    maxConnectionAgeMilliS 
         = ::getOrDefault<int> (propertyTree,
                                section + "maximumConnectionAgeInMilliSeconds",
                                maxConnectionAgeMilliS);
    options.setMaximumConnectionAge(
        std::chrono::milliseconds(maxConnectionAgeMilliS));

    int maxGracePeriodMilliS{
        static_cast<int> (options.getMaximumConnectionAgeGracePeriod().count())};
    maxGracePeriodMilliS
          = ::getOrDefault<int> (
                propertyTree,
                section + "maximumConnectionAgeGracePeriodInMilliSeconds",
                maxGracePeriodMilliS);
    options.setMaximumConnectionAgeGracePeriod(
        std::chrono::milliseconds(maxGracePeriodMilliS));

    return options;
}
