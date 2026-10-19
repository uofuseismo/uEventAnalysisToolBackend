#ifndef OTEL_OPTIONS_HPP
#define OTEL_OPTIONS_HPP
#include <chrono>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "secretFile.hpp"

namespace
{

[[nodiscard]]
std::pair<std::chrono::milliseconds, std::chrono::milliseconds>
getOTelMetricsIntervalAndTimeOut(
    boost::property_tree::ptree &propertyTree,
    const std::string &section,
    const std::chrono::milliseconds &defaultExportInterval,
    const std::chrono::milliseconds &defaultExportTimeOut)
{
    int64_t exportInterval = defaultExportInterval.count();
    exportInterval
        = propertyTree.get<int64_t> (
            section + ".exportIntervalInMilliSeconds",
            exportInterval);
    if (exportInterval <= 0)
    {   
        throw std::runtime_error("Export interval must be positive");
    }   
    int64_t exportTimeOut = defaultExportTimeOut.count();
    exportTimeOut
        = propertyTree.get<int64_t> (
            section + ".exportTimeOutInMilliSeconds",
            exportTimeOut);
    if (exportTimeOut <= 0)
    {   
        throw std::invalid_argument("Export time out must be positive");
    }   
    return std::pair {std::chrono::milliseconds {exportInterval},
                      std::chrono::milliseconds {exportTimeOut}};
}

[[nodiscard]]
std::string getOTelCollectorURL(boost::property_tree::ptree &propertyTree,
                                const std::string &section)
{
    std::string result;
    std::string otelCollectorHost;
    if (propertyTree.get<bool> (section + ".getHostFromEnvironment", false))
    {
        auto hostPtr = getenv("OTEL_COLLECTOR_HOST"); 
        if (hostPtr)
        {
            if (std::strlen(hostPtr) > 0)
            {
                 otelCollectorHost = std::string{hostPtr};
            }
        }
    }
    if (otelCollectorHost.empty())
    {
        otelCollectorHost
            = propertyTree.get<std::string> (section + ".host", "");
    }
    const uint16_t otelCollectorPort
        = propertyTree.get<uint16_t> (section + ".port", 4218);
    if (!otelCollectorHost.empty())
    {   
        result = otelCollectorHost + ":" 
               + std::to_string(otelCollectorPort);
    }   
    return result;
}

}

namespace UEventAnalysisToolBackend::OTelOptions
{

struct GRPCMetrics
{
    std::string url{"localhost:4317"};
    std::chrono::milliseconds exportInterval{std::chrono::seconds {15}};
    std::chrono::milliseconds exportTimeOut{500};
    std::filesystem::path certificatePath; // Path to the cert file
};

struct GRPCLog
{
    std::string url{"localhost:4317"};
    std::chrono::milliseconds exportTimeOut{500};
    std::filesystem::path certificatePath; // Path to the cert file
};


struct HTTPMetrics
{
    std::string url{"localhost:4318"};
    std::chrono::milliseconds exportInterval{std::chrono::seconds {15}};
    std::chrono::milliseconds exportTimeOut{500};
    std::string suffix{"/v1/metrics"};
};

struct HTTPLog
{
    std::string url{"localhost:4318"};
    std::filesystem::path certificatePath;
    std::string suffix{"/v1/logs"};
};


std::optional<HTTPLog>
getHTTPLogOptionsFromIniFile(
    boost::property_tree::ptree &propertyTree,
    const std::string &section = "OTelHTTPLogOptions")
{
    if (!propertyTree.get_optional<std::string> (section))
    {
        return std::nullopt;
    }
    HTTPLog logOptions;
    logOptions.url
        = ::getOTelCollectorURL(propertyTree, section);
    logOptions.suffix
        = propertyTree.get<std::string> (section + ".suffix", "/v1/logs");
    if (!logOptions.url.empty())
    {
        if (!logOptions.suffix.empty())
        {
            if (!logOptions.url.ends_with("/") &&
                !logOptions.suffix.starts_with("/"))
            {
                logOptions.suffix = "/" + logOptions.suffix;
            }
        }
    }
    return std::make_optional<HTTPLog> (logOptions);
}

std::optional<GRPCLog>
getGRPCLogOptionsFromIniFile(
    boost::property_tree::ptree &propertyTree,
    const std::string &section = "OTelGRPCLogOptions")
{
#ifndef WITH_OTLP_GRPC
    throw std::runtime_error(
        "Recompile with Conan to use gRPC logs exporter option");
#endif
    if (!propertyTree.get_optional<std::string> (section))
    {
        return std::nullopt;
    }
    GRPCLog logOptions;
    logOptions.url
        = ::getOTelCollectorURL(propertyTree, section);
    auto certificatePath
        = propertyTree.get_optional<std::string> (section + ".certificate");
    if (certificatePath)
    {
        if (std::filesystem::exists(*certificatePath))
        {
            logOptions.certificatePath = *certificatePath;
        }
    }
    return std::make_optional<GRPCLog> (logOptions);
}

std::optional<HTTPMetrics>
getHTTPMetricsOptionsFromIniFile(
    boost::property_tree::ptree &propertyTree,
    const std::string &section = "OTelHTTPMetricsOptions")
{
    if (!propertyTree.get_optional<std::string> (section))
    {
        return std::nullopt;
    }
    HTTPMetrics metricsOptions;
    metricsOptions.url
        = ::getOTelCollectorURL(propertyTree, section);
    metricsOptions.suffix
        = propertyTree.get<std::string> (section + ".suffix",
                                         "/v1/metrics");
    if (!metricsOptions.url.empty())
    {
        if (!metricsOptions.suffix.empty())
        {
            if (!metricsOptions.url.ends_with("/") &&
                !metricsOptions.suffix.starts_with("/"))
            {
                metricsOptions.suffix = "/" + metricsOptions.suffix;
            }
        }
    }
    if (!metricsOptions.url.empty())
    {
        auto [exportInterval, exportTimeOut]
            = ::getOTelMetricsIntervalAndTimeOut(
                 propertyTree,
                 section,
                 metricsOptions.exportInterval,
                 metricsOptions.exportTimeOut);
        metricsOptions.exportInterval = exportInterval;
        metricsOptions.exportTimeOut = exportTimeOut;
    }
    return std::make_optional<HTTPMetrics> (metricsOptions);
}

std::optional<GRPCMetrics>
getGRPCMetricsOptionsFromIniFile(
    boost::property_tree::ptree &propertyTree,
    const std::string &section = "OTelGRPCMetricsOptions")
{   
#ifndef WITH_OTLP_GRPC
    throw std::runtime_error(
        "Recompile with Conan to use gRPC metrics exporter option");
#endif
    if (!propertyTree.get_optional<std::string> (section))
    {
        return std::nullopt;
    }
    GRPCMetrics metricsOptions;
    metricsOptions.url
        = getOTelCollectorURL(propertyTree, section);
    auto [exportInterval, exportTimeOut]
        = ::getOTelMetricsIntervalAndTimeOut(
              propertyTree,
              section,
              metricsOptions.exportInterval,
              metricsOptions.exportTimeOut);
    metricsOptions.exportInterval = exportInterval;
    metricsOptions.exportTimeOut = exportTimeOut;
    auto certificatePath
        = propertyTree.get_optional<std::string>
          (section + ".certificate");
    if (certificatePath)
    {
        if (std::filesystem::exists(*certificatePath))
        {
            metricsOptions.certificatePath = *certificatePath;
        }
    }
    return std::make_optional<GRPCMetrics> (metricsOptions);
}

}
#endif
