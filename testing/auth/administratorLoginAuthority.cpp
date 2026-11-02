#include <cctype>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <pqxx/pqxx>
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/administratorTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"
#include "uEventAnalysisToolBackend/database/credentials.hpp"
#include "integrationDatabase.hpp"

using namespace UEventAnalysisToolBackend::Auth;

// Integration test: the administrator login against a real auth schema.
// The authority connects as the backend role (UEAT_TEST_DB_USER); the
// users it logs in are seeded, and removed afterwards, through a superuser
// connection (UEAT_TEST_DB_SUPERUSER) because auth.add_user is granted to
// no role.  Every name carries a random suffix so the run touches only its
// own rows.

namespace
{

using Result = IAuthenticator::Result;

const std::string issuer{"ueat-admin-login-test"};
const std::string password{"green eggs and ham"};

[[nodiscard]] std::string loadKey(const std::string &fileName)
{
    const auto path
        = std::filesystem::path{TESTING_DATA_DIR}/"keys"/fileName;
    std::ifstream file{path};
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open " + path.string());
    }
    std::stringstream contents;
    contents << file.rdbuf();
    return contents.str();
}

/// @brief Seeds the users and removes them again, as a superuser.
class Seeder
{
public:
    explicit Seeder(const UEventAnalysisToolBackend::Database::Credentials &credentials) :
        mConnection(std::make_unique<pqxx::connection>
                    (credentials.getConnectionString()))
    {
        // The cheapest hash libsodium allows; verify reads the cost from
        // the hash itself, so the authority needs no matching options.
        Password::HasherOptions options;
        options.setMemoryLimitInBytes(8192);
        mHash = Password::Hasher{options}.hash(password);
    }
    void addUser(const std::string &name, const bool isAdministrator)
    {
        pqxx::work transaction{*mConnection};
        const auto added
            = transaction.exec("SELECT auth.add_user($1, $2, $3)",
                               pqxx::params {name, mHash, isAdministrator})
                         .one_row()[0].as<bool> ();
        transaction.commit();
        if (!added){throw std::runtime_error("Could not add " + name);}
        mNames.push_back(name);
    }
    /// @brief An administrator still holding an issued password.  There is
    ///        no ungated function for this, so set the column directly.
    void addProvisionalAdministrator(const std::string &name)
    {
        pqxx::work transaction{*mConnection};
        const auto added
            = transaction.exec(
                  "SELECT auth.add_provisional_user($1, $2, INTERVAL '1 hour')",
                  pqxx::params {name, mHash}).one_row()[0].as<bool> ();
        transaction.exec("UPDATE auth.users SET is_admin = TRUE "
                         " WHERE name = $1",
                         pqxx::params {name});
        transaction.commit();
        if (!added){throw std::runtime_error("Could not add " + name);}
        mNames.push_back(name);
    }
    /// @result True if the user's last_login has been set.
    [[nodiscard]] bool hasLoggedIn(const std::string &name)
    {
        pqxx::nontransaction transaction{*mConnection};
        return !transaction.exec("SELECT last_login FROM auth.users "
                                 " WHERE name = $1",
                                 pqxx::params {name}).one_row()[0].is_null();
    }
    ~Seeder()
    {
        for (const auto &name : mNames)
        {
            try
            {
                pqxx::work transaction{*mConnection};
                transaction.exec("SELECT auth.remove_user($1)",
                                 pqxx::params {name});
                transaction.commit();
            }
            catch (const std::exception &e)
            {
                // Can't fail the test from a destructor; say so instead.
                // The suffix keeps a leftover row from colliding with the
                // next run.
                std::cerr << "Could not remove test user " << name
                          << ": " << e.what() << '\n';
            }
        }
    }
    Seeder(const Seeder &) = delete;
    Seeder(Seeder &&) = delete;
    Seeder& operator=(const Seeder &) = delete;
    Seeder& operator=(Seeder &&) = delete;
private:
    std::unique_ptr<pqxx::connection> mConnection;
    std::vector<std::string> mNames;
    std::string mHash;
};

}

TEST_CASE("UEventAnalysisToolBackend::Auth::AdministratorLoginAuthority",
          "[.integration][AdministratorLoginAuthority]")
{
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-admin-login-test-" + suffix;
    const auto backendCredentials
        = IntegrationDatabase::credentials(application);
    const auto superuserCredentials
        = IntegrationDatabase::superuserCredentials(application + "-seeder");
    if (!backendCredentials || !superuserCredentials)
    {
        SKIP("Set UEAT_TEST_DB_{HOST,PORT,NAME,USER,PASSWORD} and "
             "UEAT_TEST_DB_SUPERUSER{,_PASSWORD} to run this");
    }

    // N.B. auth.* lower-cases names, so these are written lower case.
    const std::string administrator{"sam-i-am-" + suffix};
    const std::string user{"guy-am-i-" + suffix};
    const std::string provisional{"sam-i-am-provisional-" + suffix};
    INFO("suffix = " << suffix);

    Seeder seeder{*superuserCredentials};
    seeder.addUser(administrator, true);
    seeder.addUser(user, false);
    seeder.addProvisionalAdministrator(provisional);

    const auto publicKey = loadKey("ed25519-admin-public-key.pem");
    AdministratorLoginAuthorityOptions options;
    options.setDatabaseCredentials(*backendCredentials);
    options.setKeyPairAndAlgorithm(
        std::pair {publicKey, loadKey("ed25519-admin-private-key.pem")},
        AdministratorLoginAuthorityOptions::Algorithm::EdDSA25519);
    options.setIssuer(issuer);
    options.setTimeToLive(std::chrono::minutes {10});
    const AdministratorLoginAuthority authority{
        options,
        IntegrationDatabase::quietLogger("administratorLoginAuthorityTests")};
    REQUIRE(authority.isInitialized());

    TokenVerifierOptions verifierOptions;
    verifierOptions.setPublicKeyAndAlgorithm(
        publicKey, TokenVerifierOptions::Algorithm::EdDSA25519);
    verifierOptions.setIssuer(issuer);
    const AdministratorTokenVerifier verifier{
        verifierOptions,
        IntegrationDatabase::quietLogger("administratorLoginAuthorityTests")};

    SECTION("An administrator with the right password gets a token")
    {
        const auto token
            = authority.loginWithPassword(std::pair {administrator, password});
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        if (claims)
        {
            REQUIRE(claims->getUser() == administrator);
            REQUIRE(Claims::isAdministrator(*claims));
        }
        REQUIRE(seeder.hasLoggedIn(administrator));
    }
    SECTION("The user name is matched case-insensitively, as in the SQL")
    {
        auto shouted = administrator;
        for (auto &c : shouted){c = static_cast<char> (std::toupper(c));}
        REQUIRE(authority.loginWithPassword(std::pair {shouted, password})
                    .has_value());
    }
    SECTION("An administrator with the wrong password is refused")
    {
        const auto token
            = authority.loginWithPassword(
                 std::pair {administrator, std::string {"green eggs"}});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
        REQUIRE_FALSE(seeder.hasLoggedIn(administrator));
    }
    SECTION("A non-administrator with the right password is refused")
    {
        const auto token
            = authority.loginWithPassword(std::pair {user, password});
        REQUIRE_FALSE(token.has_value());
        // The same answer as a wrong password: the caller learns nothing
        // about who the administrators are.
        REQUIRE(token.error() == Result::InvalidCredentials);
        // Refused before the login is recorded.
        REQUIRE_FALSE(seeder.hasLoggedIn(user));
    }
    SECTION("A provisional administrator is refused")
    {
        // Holding an issued password proves only that it was received.
        const auto token
            = authority.loginWithPassword(std::pair {provisional, password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
    }
    SECTION("An unknown user is refused")
    {
        const auto token
            = authority.loginWithPassword(
                 std::pair {"no-such-user-" + suffix, password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
    }
    SECTION("An empty user name is refused")
    {
        const auto token
            = authority.loginWithPassword(std::pair {std::string {}, password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
    }
}
