#ifndef PROGRAM_OPTIONS_HPP
#define PROGRAM_OPTIONS_HPP
#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "uEventAnalysisToolBackend/database/credentials.hpp"
#include "uEventAnalysisToolBackend/auth/databaseOptions.hpp"
#include "uEventAnalysisToolBackend/auth/jsonWebTokenOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolBackend/grpc/serverOptions.hpp"
#include "uEventAnalysisToolBackend/grpc/grpcServerOptions.hpp"
#include "otelOptions.hpp"

#define APPLICATION_NAME "uEventAnalysisToolBackend"
#define PRINT_SUMMARY_INTERVAL_MINUTES 15

namespace
{

[[nodiscard]] std::string
loadStringFromFile(const std::filesystem::path &path)
{
    std::string result;
    if (!std::filesystem::exists(path)){return result;}
    std::ifstream file(path);
    if (!file.is_open())
    {   
        throw std::runtime_error("Failed to open " + path.string());
    }   
    std::stringstream sstr;
    sstr << file.rdbuf();
    file.close(); 
    result = sstr.str();
    return result;
}

struct MapServerOptions
{
    enum class Service
    {
        Stadia
    };
    void fromPropertyTree(boost::property_tree::ptree &propertyTree)
    {
        auto mapService = propertyTree.get<std::string> ("MapService.service");
        std::transform(mapService.begin(), mapService.end(),
                       mapService.begin(), ::tolower);
        if (mapService == "stadia" || mapService == "stadiamaps")
        {
            service = Service::Stadia;
        }
        else
        {
            throw std::invalid_argument("Unhandled MapService.service "
                                      + mapService + " - must be stadia");
        }
        key = propertyTree.get<std::string> ("MapService.key"); 
        if (key.empty())
        {
            throw std::invalid_argument("MapService.key not specified");
        }
    }
    Service service; 
    std::string key;
};

struct ProgramOptions
{
    void parseInitializationFile(const std::filesystem::path &iniFile)
    {
        namespace UEAT = UEventAnalysisToolBackend;
        if (!std::filesystem::exists(iniFile))
        {
            throw std::invalid_argument("Initialization file "
                                      + std::string {iniFile}
                                      + " does not exist");
        }
        // Parse the initialization file
        boost::property_tree::ptree propertyTree;
        boost::property_tree::ini_parser::read_ini(iniFile, propertyTree);
        applicationName
            = propertyTree.get<std::string> ("General.applicationName",
                                             applicationName);
        if (applicationName.empty()){applicationName = APPLICATION_NAME;}
        verbosity
            = propertyTree.get<int> ("General.verbosity", verbosity);

        auto printSummaryIntervalInMinutes
            = propertyTree.get<int> ("General.printSummaryIntervalInMinutes",
                                     PRINT_SUMMARY_INTERVAL_MINUTES);
        printSummaryInterval = std::chrono::minutes {printSummaryIntervalInMinutes};

        mapServerOptions.fromPropertyTree(propertyTree);

        // TODO eventually this goes away but for now we need test data
        aqmsCredentials
            = UEAT::Database::Credentials::fromInitializationFile(
                 iniFile, "AQMS");

        // Server grpc options
        auto serverGRPCOptions
            = UEAT::GRPC::GRPCServerOptions::fromInitializationFile(
                 iniFile, "GRPCServer"); 

        // Backend database
        backendDatabaseCredentials
            = UEAT::Database::Credentials::fromInitializationFile(
                 iniFile, "Database");
 
        jwtOptions
            = UEAT::Auth::JSONWebTokenOptions::fromInitializationFile(
                 iniFile, "Authentication");
        passwordHasherOptions
            = UEAT::Auth::Password::HasherOptions::fromInitializationFile(
                 iniFile, "PasswordHasher");
        passwordPolicy
            = UEAT::Auth::Password::PasswordPolicy::fromInitializationFile(
                 iniFile, "PasswordPolicy");
    }
//private:
    UEventAnalysisToolBackend::OTelOptions::HTTPMetrics otelHTTPMetricsOptions;
    UEventAnalysisToolBackend::OTelOptions::HTTPLog otelHTTPLogOptions;
    UEventAnalysisToolBackend::OTelOptions::GRPCMetrics otelGRPCMetricsOptions;
    UEventAnalysisToolBackend::OTelOptions::GRPCLog otelGRPCLogOptions;
    UEventAnalysisToolBackend::Database::Credentials backendDatabaseCredentials;
    UEventAnalysisToolBackend::Auth::JSONWebTokenOptions jwtOptions;
    UEventAnalysisToolBackend::Auth::Password::HasherOptions passwordHasherOptions;
    UEventAnalysisToolBackend::Auth::Password::PasswordPolicy passwordPolicy;
    UEventAnalysisToolBackend::Auth::DatabaseOptions authDatabaseOptions;
    UEventAnalysisToolBackend::GRPC::ServerOptions mGRPCServerOptions;
    MapServerOptions mapServerOptions;
    std::string applicationName{APPLICATION_NAME};
    std::chrono::seconds printSummaryInterval
    {
        std::chrono::minutes {PRINT_SUMMARY_INTERVAL_MINUTES}
    };
    int verbosity{3};
    bool exportMetrics{false};
    bool exportLogs{false};
    bool exportLogsWithHTTP{true};

    UEventAnalysisToolBackend::Database::Credentials aqmsCredentials;
};

}
#endif
