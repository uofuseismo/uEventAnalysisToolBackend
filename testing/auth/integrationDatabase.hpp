#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_TESTING_AUTH_INTEGRATION_DATABASE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_TESTING_AUTH_INTEGRATION_DATABASE_HPP
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <spdlog/logger.h>
#include <spdlog/sinks/null_sink.h>
#include "uEventAnalysisToolBackend/database/credentials.hpp"

// Shared plumbing for the [.integration] tests.  They need a database
// built by scripts/database/create.sh and are configured by
//
//   UEAT_TEST_DB_HOST, UEAT_TEST_DB_PORT, UEAT_TEST_DB_NAME
//   UEAT_TEST_DB_USER, UEAT_TEST_DB_PASSWORD          - the backend role
//   UEAT_TEST_DB_SUPERUSER, UEAT_TEST_DB_SUPERUSER_PASSWORD
//                                                     - seeding, if needed
//
// Never point these at a database you care about: the tests add and
// remove users and terminate their own sessions.

namespace IntegrationDatabase
{

[[nodiscard]] inline std::optional<std::string> environment(const char *name)
{
    const char *value = std::getenv(name); // NOLINT(concurrency-mt-unsafe)
    if (value == nullptr || *value == '\0'){return std::nullopt;}
    return std::string {value};
}

/// @result A random suffix so concurrent or aborted runs never collide.
[[nodiscard]] inline std::string uniqueSuffix()
{
    std::random_device device;
    std::uniform_int_distribution<std::uint32_t> distribution;
    return std::to_string(distribution(device));
}

/// @param[in] application   The application_name the sessions carry.
/// @param[in] userVariable  The environment variable holding the role.
/// @param[in] passwordVariable  The environment variable holding its
///                              password.
/// @result The credentials, or nothing if any variable is unset.
[[nodiscard]] inline std::optional<UEventAnalysisToolBackend::Database::Credentials>
    credentials(const std::string &application,
                const char *userVariable = "UEAT_TEST_DB_USER",
                const char *passwordVariable = "UEAT_TEST_DB_PASSWORD")
{
    const auto host = environment("UEAT_TEST_DB_HOST");
    const auto port = environment("UEAT_TEST_DB_PORT");
    const auto name = environment("UEAT_TEST_DB_NAME");
    const auto user = environment(userVariable);
    const auto password = environment(passwordVariable);
    if (!host || !port || !name || !user || !password){return std::nullopt;}
    UEventAnalysisToolBackend::Database::Credentials result;
    result.setHost(*host);
    result.setPort(static_cast<std::uint16_t> (std::stoi(*port)));
    result.setDatabaseName(*name);
    result.setUser(*user);
    result.setPassword(*password);
    result.setApplication(application);
    result.setTimeOut(std::chrono::seconds {5});
    return result;
}

[[nodiscard]] inline std::optional<UEventAnalysisToolBackend::Database::Credentials>
    superuserCredentials(const std::string &application)
{
    return credentials(application,
                       "UEAT_TEST_DB_SUPERUSER",
                       "UEAT_TEST_DB_SUPERUSER_PASSWORD");
}

[[nodiscard]] inline std::shared_ptr<spdlog::logger>
    quietLogger(const std::string &name)
{
    return std::make_shared<spdlog::logger>(
        name, std::make_shared<spdlog::sinks::null_sink_mt> ());
}

}
#endif
