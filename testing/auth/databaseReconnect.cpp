#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <pqxx/pqxx>
#include <spdlog/logger.h>
#include "uEventAnalysisToolBackend/database/credentials.hpp"
#include "auth/databaseUtilities.hpp"
#include "integrationDatabase.hpp"

// Tests the private connection base the login authorities inherit.
//
// The integration case kills the connection's session from a second
// connection, as a Postgres restart or a dropped network would, and checks
// the next call reconnects.  Only sessions carrying this run's unique
// application_name are terminated, so other clients of the same role are
// left alone.  It needs no schema - it runs SELECT 1.  Run it with
//
//   UEAT_TEST_DB_HOST=127.0.0.1 UEAT_TEST_DB_PORT=... \
//   UEAT_TEST_DB_NAME=... UEAT_TEST_DB_USER=... UEAT_TEST_DB_PASSWORD=... \
//   ./unitTests "[integration]"

namespace
{

namespace Detail = UEventAnalysisToolBackend::Auth::Detail;

/// @brief The base's destructor is protected, so it can only be tested
///        through a derived class - as the authorities use it.
class Probe : public Detail::DatabaseConnection::Database
{
public:
    Probe(const UEventAnalysisToolBackend::Database::Credentials &credentials,
          std::shared_ptr<spdlog::logger> logger) :
        Database{"databaseReconnectTests", credentials, std::move(logger)}
    {
        // The real 2 s/15 s waits would make the tests slow and prove
        // nothing more.
        mRetrySchedule = {std::chrono::milliseconds {0},
                          std::chrono::milliseconds {100},
                          std::chrono::milliseconds {100}};
    }
    [[nodiscard]] int selectOne()
    {
        return withTransaction<pqxx::read_transaction>(
            [](pqxx::read_transaction &transaction) -> int
            {
                auto value
                    = transaction.exec("SELECT 1").one_row()[0].as<int> ();
                transaction.commit();
                return value;
            });
    }
};

/// @brief A second connection, under a different application_name, that
///        watches and terminates the probe's sessions.
class SessionKiller
{
public:
    SessionKiller(UEventAnalysisToolBackend::Database::Credentials credentials,
                  std::string target) :
        mTarget(std::move(target))
    {
        credentials.setApplication(mTarget + "-killer");
        mConnection
            = std::make_unique<pqxx::connection>
              (credentials.getConnectionString());
    }
    /// @result The number of live sessions with the target's name.
    [[nodiscard]] int sessions()
    {
        pqxx::nontransaction transaction{*mConnection};
        return transaction.exec(
                   "SELECT count(*) FROM pg_stat_activity "
                   "WHERE application_name = $1",
                   pqxx::params {mTarget}).one_row()[0].as<int> ();
    }
    /// @result The number of sessions signalled.
    [[nodiscard]] int terminate()
    {
        // N.B. The CTE must be MATERIALIZED.  Written as one WHERE,
        // Postgres may call pg_terminate_backend before testing the name
        // - and then kills every session the role can see, this one too.
        pqxx::nontransaction transaction{*mConnection};
        return transaction.exec(
                   "WITH targets AS MATERIALIZED ("
                   "    SELECT pid FROM pg_stat_activity"
                   "     WHERE application_name = $1"
                   "       AND pid <> pg_backend_pid()) "
                   "SELECT count(*) FROM targets "
                   " WHERE pg_terminate_backend(pid)",
                   pqxx::params {mTarget}).one_row()[0].as<int> ();
    }
    /// @brief pg_terminate_backend only signals; wait for the session to
    ///        actually go.
    [[nodiscard]] bool waitUntilGone()
    {
        const auto deadline
            = std::chrono::steady_clock::now() + std::chrono::seconds {5};
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (sessions() == 0){return true;}
            std::this_thread::sleep_for(std::chrono::milliseconds {50});
        }
        return false;
    }
private:
    std::string mTarget;
    std::unique_ptr<pqxx::connection> mConnection;
};

}

TEST_CASE("UEventAnalysisToolBackend::Auth::Detail::DatabaseConnection "
          "gives up on an unreachable server",
          "[DatabaseConnection]")
{
    // Nothing listens on port 1, so every attempt is refused at once.
    UEventAnalysisToolBackend::Database::Credentials credentials;
    credentials.setHost("127.0.0.1");
    credentials.setPort(1);
    credentials.setDatabaseName("ueat-no-such-database");
    credentials.setUser("sam-i-am");
    credentials.setPassword("green eggs and ham");
    credentials.setTimeOut(std::chrono::seconds {1});

    // Construction does not connect, so it must not throw.
    std::unique_ptr<Probe> probe;
    REQUIRE_NOTHROW(probe = std::make_unique<Probe>
                    (credentials,
                     IntegrationDatabase::quietLogger("databaseReconnectTests")));
    REQUIRE_FALSE(probe->isConnected());
    // The schedule is exhausted and the caller gets the one exception type,
    // not a pqxx one.
    REQUIRE_THROWS_AS(probe->selectOne(), std::runtime_error);
    REQUIRE_FALSE(probe->isConnected());
}

TEST_CASE("UEventAnalysisToolBackend::Auth::Detail::DatabaseConnection "
          "reconnects",
          "[.integration][DatabaseConnection]")
{
    const auto applicationName
        = "ueat-reconnect-test-" + IntegrationDatabase::uniqueSuffix();
    const auto credentials = IntegrationDatabase::credentials(applicationName);
    if (!credentials)
    {
        SKIP("Set UEAT_TEST_DB_{HOST,PORT,NAME,USER,PASSWORD} to run this");
    }
    INFO("application_name = " << applicationName);

    Probe probe{*credentials,
                IntegrationDatabase::quietLogger("databaseReconnectTests")};
    SessionKiller killer{*credentials, applicationName};

    // Connecting is lazy: nothing until the first call.
    REQUIRE_FALSE(probe.isConnected());
    REQUIRE(killer.sessions() == 0);
    REQUIRE(probe.selectOne() == 1);
    REQUIRE(probe.isConnected());
    REQUIRE(killer.sessions() == 1);

    SECTION("A terminated session is replaced on the next call")
    {
        // Twice, so the second loss is of a connection the retry made.
        for (int loss = 1; loss <= 2; ++loss)
        {
            INFO("loss " << loss);
            REQUIRE(killer.terminate() == 1);
            REQUIRE(killer.waitUntilGone());

            int value{0};
            REQUIRE_NOTHROW(value = probe.selectOne());
            REQUIRE(value == 1);
            // Exactly one replacement session, not one per attempt.
            REQUIRE(killer.sessions() == 1);
        }
    }
    SECTION("disconnect closes the session and the next call reopens it")
    {
        probe.disconnect();
        REQUIRE_FALSE(probe.isConnected());
        REQUIRE(killer.waitUntilGone());
        REQUIRE(probe.selectOne() == 1);
        REQUIRE(killer.sessions() == 1);
    }
}
