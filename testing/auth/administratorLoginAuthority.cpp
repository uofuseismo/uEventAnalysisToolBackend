#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/administratorTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"
#include "integrationDatabase.hpp"
#include "userSeeder.hpp"

using namespace UEventAnalysisToolBackend::Auth;

// Integration test: the administrator step-up against a real auth schema.
// The authority connects as the backend role (UEAT_TEST_DB_USER); the
// users it elevates are seeded, and removed afterwards, through a
// superuser connection (UEAT_TEST_DB_SUPERUSER).  Every name carries a
// random suffix so the run touches only its own rows.
//
// The step-up takes the claims of an already-verified user token, so the
// tests build those claims directly rather than minting a user token.

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

/// @result The claims of a verified user token for this user.
[[nodiscard]] Claims userClaims(
    const std::string &user,
    const std::chrono::system_clock::time_point expiresAt
        = std::chrono::system_clock::now() + std::chrono::hours {1})
{
    return Claims{user,
                  Claims::Scope::User,
                  std::vector<std::pair<std::string, std::string>> {},
                  expiresAt};
}

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

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(administrator, true);
    seeder.addUser(user, false);
    seeder.addProvisionalUser(provisional, true);

    const auto publicKey = loadKey("ed25519-admin-public-key.pem");
    const std::chrono::minutes timeToLive{10};
    AdministratorLoginAuthorityOptions options;
    options.setDatabaseCredentials(*backendCredentials);
    options.setKeyPairAndAlgorithm(
        std::pair {publicKey, loadKey("ed25519-admin-private-key.pem")},
        AdministratorLoginAuthorityOptions::Algorithm::EdDSA25519);
    options.setIssuer(issuer);
    options.setTimeToLive(timeToLive);
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
            = authority.loginWithPassword(userClaims(administrator), password);
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        if (claims)
        {
            REQUIRE(claims->getUser() == administrator);
            REQUIRE(Claims::isAdministrator(*claims));
            // A step-up token grants administration, not data access.
            REQUIRE(claims->begin() == claims->end());
        }
        REQUIRE(seeder.hasLoggedIn(administrator));
    }
    SECTION("The admin token lives no longer than its time to live")
    {
        const auto before = std::chrono::system_clock::now();
        const auto token
            = authority.loginWithPassword(userClaims(administrator), password);
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(claims.has_value());
        if (claims)
        {
            // exp is whole seconds, so allow one either side.
            const auto expiresAt = claims->getExpirationTime();
            REQUIRE(expiresAt >= before + timeToLive - std::chrono::seconds {1});
            REQUIRE(expiresAt <= std::chrono::system_clock::now()
                               + timeToLive + std::chrono::seconds {1});
        }
    }
    SECTION("The admin token cannot outlive the user token it came from")
    {
        // The user token expires well inside the admin time to live.
        const auto userExpiresAt
            = std::chrono::system_clock::now() + std::chrono::minutes {2};
        const auto token
            = authority.loginWithPassword(
                  userClaims(administrator, userExpiresAt), password);
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        if (claims)
        {
            REQUIRE(claims->getExpirationTime() <= userExpiresAt);
            REQUIRE(claims->getExpirationTime()
                 >= userExpiresAt - std::chrono::seconds {1});
        }
    }
    SECTION("An expired user token cannot be elevated")
    {
        // requireBearer would have refused this; the authority must too,
        // or it would mint a token that is dead on arrival.
        const auto token
            = authority.loginWithPassword(
                  userClaims(administrator,
                             std::chrono::system_clock::now()
                           - std::chrono::seconds {1}),
                  password);
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
        REQUIRE_FALSE(seeder.hasLoggedIn(administrator));
    }
    SECTION("The user name is matched case-insensitively, as in the SQL")
    {
        auto shouted = administrator;
        for (auto &c : shouted){c = static_cast<char> (std::toupper(c));}
        REQUIRE(authority.loginWithPassword(userClaims(shouted), password)
                    .has_value());
    }
    SECTION("An administrator with the wrong password is refused")
    {
        const auto token
            = authority.loginWithPassword(userClaims(administrator),
                                          "green eggs");
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
        REQUIRE_FALSE(seeder.hasLoggedIn(administrator));
    }
    SECTION("A non-administrator with the right password is refused")
    {
        const auto token
            = authority.loginWithPassword(userClaims(user), password);
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
            = authority.loginWithPassword(userClaims(provisional), password);
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
    }
    SECTION("An unknown user is refused")
    {
        const auto token
            = authority.loginWithPassword(
                 userClaims("no-such-user-" + suffix), password);
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
    }
    SECTION("An empty user name is refused")
    {
        const auto token
            = authority.loginWithPassword(userClaims(std::string {}),
                                          password);
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
    }
}
