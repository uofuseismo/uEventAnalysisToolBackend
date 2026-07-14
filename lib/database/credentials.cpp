#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include "uEventAnalysisToolBackend/database/credentials.hpp"

#define DRIVER "postgresql"

using namespace UEventAnalysisToolBackend::Database;

class Credentials::CredentialsImpl
{
public:
    std::string mConnectionString;
    std::string mUser;
    std::string mPassword;
    std::string mDatabaseName;
    std::string mHost{"localhost"};
    std::optional<std::string> mSchema;
    std::string mApplication{"uEventAnalysisToolBackend"};
    std::chrono::milliseconds mTimeOut{std::chrono::seconds{5}};
    uint16_t mPort{5432};
    bool mReadOnly{true};
};

/// Constructor
Credentials::Credentials() :
    pImpl(std::make_unique<CredentialsImpl> ())
{
}

/// Copy constructor
Credentials::Credentials(const Credentials &credentials)
{
    *this = credentials;
}

/// Move constructor
Credentials::Credentials(Credentials &&credentials) noexcept
{
    *this = std::move(credentials);
}

/// Move assignment
Credentials& Credentials::operator=(Credentials &&credentials) noexcept
{
    if (&credentials == this){return *this;}
    pImpl = std::move(credentials.pImpl);
    return *this;
}

/// Copy assignment
Credentials& Credentials::operator=(const Credentials &credentials)
{
    if (&credentials == this){return *this;}
    pImpl = std::make_unique<CredentialsImpl> (*credentials.pImpl);
    return *this;
}

/// Destructor
Credentials::~Credentials() = default; 

/// User
void Credentials::setUser(const std::string &user)
{
    if (user.empty())
    {
        throw std::invalid_argument("User is empty");
    }
    pImpl->mConnectionString.clear();
    pImpl->mUser = user;
}

std::string Credentials::getUser() const
{
    if (!hasUser()){throw std::runtime_error("User not set");}
    return pImpl->mUser;
}

bool Credentials::hasUser() const noexcept
{
    return !pImpl->mUser.empty();
}

/// Password
void Credentials::setPassword(const std::string &password)
{
    if (password.empty())
    {
        throw std::invalid_argument("Password is empty");
    }
    pImpl->mConnectionString.clear();
    pImpl->mPassword = password;
}

std::string Credentials::getPassword() const
{
    if (!hasPassword()){throw std::runtime_error("Password not set");}
    return pImpl->mPassword;
}

bool Credentials::hasPassword() const noexcept
{
    return !pImpl->mPassword.empty();
}

/// Host
void Credentials::setHost(const std::string &host)
{
    if (host.empty())
    {
        throw std::invalid_argument("Host is empty");
    }
    pImpl->mConnectionString.clear();
    pImpl->mHost = host;
}

std::string Credentials::getHost() const noexcept
{
    return pImpl->mHost;
}

/// DB name
void Credentials::setDatabaseName(const std::string &name)
{
    if (name.empty())
    {
        throw std::invalid_argument("Name is empty");
    }
    pImpl->mConnectionString.clear();
    pImpl->mDatabaseName = name;
}

std::string Credentials::getDatabaseName() const
{
    if (!hasDatabaseName()){throw std::runtime_error("Database name not set");}
    return pImpl->mDatabaseName;
}

bool Credentials::hasDatabaseName() const noexcept
{
    return !pImpl->mDatabaseName.empty();
}

/// Port
void Credentials::setPort(const uint16_t port)
{
    if (port < 0){throw std::invalid_argument("Port cannot be negative");}
    pImpl->mConnectionString.clear();
    pImpl->mPort = port;
}

uint16_t Credentials::getPort() const noexcept
{
    return pImpl->mPort;
}

/// Application
void Credentials::setApplication(const std::string &application)
{
    if (application.empty())
    {
        throw std::invalid_argument("Application is empty");
    }
    pImpl->mConnectionString.clear();
    pImpl->mApplication = application;
}

std::string Credentials::getApplication() const noexcept
{
    return pImpl->mApplication;
}

/// Schema
void Credentials::setSchema(const std::string &schema)
{
    pImpl->mSchema = std::make_optional<std::string> (schema);
}

std::optional<std::string> Credentials::getSchema() const noexcept
{
    return pImpl->mSchema;
} 

/// Timeout
void Credentials::setTimeOut(const std::chrono::milliseconds &timeOut) noexcept
{
    pImpl->mTimeOut = timeOut;
}

std::chrono::milliseconds Credentials::getTimeOut() const noexcept
{
    return pImpl->mTimeOut;
}

/// Drivername
std::string Credentials::getDriver() noexcept
{
   return DRIVER;
}

/// Generate a connection string
std::string Credentials::getConnectionString() const
{
    if (!hasUser()){throw std::runtime_error("User not set");}
    if (!hasPassword()){throw std::runtime_error("Password not set");}
    auto user = getUser();
    auto password = getPassword();
    auto host = getHost();
    auto cPort = std::to_string(getPort()); 
    auto dbname = getDatabaseName();
    auto applicationName = getApplication();
    std::string cTimeOut;
    if (pImpl->mTimeOut.count() > 0)
    {
        constexpr int milliSecondsToSeconds{1000};
        cTimeOut = std::to_string(pImpl->mTimeOut.count()
                                 *milliSecondsToSeconds);
    }
    pImpl->mConnectionString = "user=" + user
                             + " password=" + password
                             + " host=" + host 
                             + " dbname=" + dbname
                             + " port=" + cPort;
   
    if (!cTimeOut.empty())
    {
        pImpl->mConnectionString = pImpl->mConnectionString
                                 + " connect_timeout=" + cTimeOut;
    }
    if (!applicationName.empty())
    {
        pImpl->mConnectionString = pImpl->mConnectionString
                                 + " application_name=" + applicationName;
    }
    return pImpl->mConnectionString;
}

/// Read-only?
void Credentials::enableReadOnly() noexcept
{
    pImpl->mReadOnly = true;
}

void Credentials::enableReadWrite() noexcept
{
    pImpl->mReadOnly = false;
}

bool Credentials::isReadOnly() const noexcept
{
    return pImpl->mReadOnly;
}

///--------------------------------------------------------------------------///
///                         Build from ini file                              ///
///--------------------------------------------------------------------------///
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>

Credentials Credentials::fromInitializationFile(
    const std::filesystem::path &iniFile,
    const std::string &sectionIn)
{
    if (!std::filesystem::exists(iniFile))
    {
        throw std::invalid_argument("Initialization " + std::string{iniFile}
                                  + " file does not exist");
    }
    // Make sure section ends with . so we can find stuff
    auto section = sectionIn;
    if (!section.empty() && section.back() != '.'){section.append(".");}

    Credentials result;

    // Parse the initialization file
    boost::property_tree::ptree propertyTree;
    boost::property_tree::ini_parser::read_ini(iniFile, propertyTree);

    // The must haves
    auto user = propertyTree.get<std::string> (section + "user");
    result.setUser(user);
 
    auto password = propertyTree.get<std::string> (section + "password");
    result.setPassword(password);

    auto database = propertyTree.get<std::string> (section + "database");
    result.setDatabaseName(database);

    // Things with defaults
    auto host = propertyTree.get<std::string> (section + "host",
                                               result.getHost());
    result.setHost(host);

    auto port = propertyTree.get<std::uint16_t> (section + "port",
                                                 result.getPort());
    result.setPort(port);

    auto schema = propertyTree.get_optional<std::string> (section + "schema"); 
    if (schema)
    {
        if (!schema->empty()){result.setSchema(*schema);}
    }

    auto application = propertyTree.get<std::string> (section + "application",
                                                      result.getApplication());
    if (!application.empty()){result.setApplication(application);}

    // Timeout
    auto timeOut = static_cast<int> (result.getTimeOut().count());
    timeOut = propertyTree.get<int> (section + "timeOutInMilliSeconds",
                                     timeOut);
    result.setTimeOut(std::chrono::milliseconds {timeOut});

    auto isReadOnly = propertyTree.get<bool> (section + "isReadOnly",
                                              result.isReadOnly());
    if (isReadOnly)
    {
        result.enableReadOnly();
    }
    else
    {
        result.enableReadWrite();
    }

    return result;
}
