#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/database/credentials.hpp"

TEST_CASE("UEventAnalysisToolBackend::Database", "Credentials")
{
    using namespace UEventAnalysisToolBackend::Database;
    SECTION("Defaults")
    {
        const std::string host{"localhost"};
        const std::string application{"uEventAnalysisToolBackend"};
        constexpr std::chrono::milliseconds timeOut{std::chrono::seconds {5}};
        constexpr uint16_t port{5432};
        const Credentials credentials;
        REQUIRE_FALSE(credentials.hasUser());
        REQUIRE_FALSE(credentials.hasPassword());
        REQUIRE_FALSE(credentials.hasDatabaseName());
        REQUIRE(credentials.getPort() == port);
        REQUIRE(credentials.getHost() == host);
        REQUIRE(credentials.getApplication() == application);
        REQUIRE(credentials.getSchema() == std::nullopt);
        REQUIRE(credentials.isReadOnly() == true);
        REQUIRE(credentials.getDriver() == "postgresql");
    }
    SECTION("Options")
    {
        const std::string user{"user"};
        const std::string password{"password"};
        const std::string host{"google.com"};
        const std::string application{"uEventAnalysisToolBackendTest"};
        const std::string databaseName{"dbster"};
        const std::string schema{"prod"};
        constexpr std::chrono::milliseconds timeOut{std::chrono::seconds {4}};
        constexpr uint16_t port{5433};
        const std::string connectionString{"user=user password=password host=google.com dbname=dbster port=5433 connect_timeout=4000000 application_name=uEventAnalysisToolBackendTest"};

        Credentials credentials;
        credentials.setUser(user);
        credentials.setPassword(password);
        credentials.setHost(host);
        credentials.setPort(port);
        credentials.setDatabaseName(databaseName);
        credentials.setApplication(application);
        credentials.setTimeOut(timeOut);
        credentials.setSchema(schema); 
        credentials.enableReadWrite();

        const Credentials copy{credentials};
        REQUIRE(copy.getUser() == user);
        REQUIRE(copy.getPassword() == password);
        REQUIRE(copy.getDatabaseName() == databaseName);
        REQUIRE(copy.getPort() == port);
        REQUIRE(copy.getHost() == host);
        REQUIRE(copy.getApplication() == application);
        //NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        REQUIRE(*copy.getSchema() == schema);
        REQUIRE_FALSE(copy.isReadOnly());
        REQUIRE(copy.getConnectionString() == connectionString);
    }
}

