#include <algorithm>
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
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "integrationDatabase.hpp"
#include "userSeeder.hpp"

using namespace UEventAnalysisToolBackend::Auth;

// Integration test: user login and password changes against a real auth
// schema.  The authority connects as the backend role (UEAT_TEST_DB_USER);
// the users are seeded, and removed afterwards, through a superuser
// connection (UEAT_TEST_DB_SUPERUSER).  Every name carries a random suffix
// so the run touches only its own rows.

namespace
{

using Result = IAuthenticator::Result;
using ChangePasswordError = UserLoginAuthority::ChangePasswordError;
using Permissions = std::vector<std::pair<std::string, std::string>>;

const std::string issuer{"ueat-user-login-test"};
// What the seeder hashes.  It satisfies no policy, which is fine: an
// issued password is never checked against one.
const std::string password{"green eggs and ham"};
// Passes the policy below.
const std::string newPassword{"green eggs and ham 42"};

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

/// @brief Spelled out rather than defaulted so the tests don't move when
///        the defaults do.
[[nodiscard]] Password::PasswordPolicy policy()
{
    Password::PasswordPolicy result;
    result.setMinimumAndMaximumLength(std::pair {12, 64});
    result.enableRequiresNumber();
    result.disableRequiresSpecialCharacter();
    result.enableNewAndOldPasswordMustDiffer();
    return result;
}

[[nodiscard]] UserLoginAuthorityOptions options(
    const UEventAnalysisToolBackend::Database::Credentials &credentials,
    const Password::HasherOptions &hasherOptions)
{
    UserLoginAuthorityOptions result;
    result.setDatabaseCredentials(credentials);
    result.setKeyPairAndAlgorithm(
        std::pair {loadKey("ed25519-public-key.pem"),
                   loadKey("ed25519-private-key.pem")},
        UserLoginAuthorityOptions::Algorithm::EdDSA25519);
    result.setIssuer(issuer);
    result.setTimeToLive(std::chrono::minutes {15});
    result.setPasswordHasherOptions(hasherOptions);
    result.setPasswordPolicy(policy());
    return result;
}

[[nodiscard]] std::string toUpper(std::string s)
{
    for (auto &c : s){c = static_cast<char> (std::toupper(c));}
    return s;
}

}

TEST_CASE("UEventAnalysisToolBackend::Auth::UserLoginAuthority",
          "[.integration][UserLoginAuthority]")
{
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-user-login-test-" + suffix;
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
    const std::string user{"guy-am-i-" + suffix};
    const std::string administrator{"sam-i-am-" + suffix};
    const std::string provisional{"guy-am-i-provisional-" + suffix};
    INFO("suffix = " << suffix);

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(user, false);
    seeder.setPermission(user, "utah", "read_write");
    seeder.setPermission(user, "sandbox_utah", "read_only");
    seeder.addUser(administrator, true);
    seeder.addProvisionalUser(provisional);

    // Hash with the seeder's settings so logging in doesn't rehash; the
    // rehash section uses its own authority.
    UserLoginAuthority authority{
        options(*backendCredentials, IntegrationDatabase::cheapHasherOptions()),
        IntegrationDatabase::quietLogger("userLoginAuthorityTests")};
    REQUIRE(authority.isInitialized());

    TokenVerifierOptions verifierOptions;
    verifierOptions.setPublicKeyAndAlgorithm(
        loadKey("ed25519-public-key.pem"),
        TokenVerifierOptions::Algorithm::EdDSA25519);
    verifierOptions.setIssuer(issuer);
    const UserTokenVerifier verifier{
        verifierOptions,
        IntegrationDatabase::quietLogger("userLoginAuthorityTests")};

    SECTION("A user with the right password gets a user token")
    {
        const auto token
            = authority.loginWithPassword(std::pair {user, password});
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        if (claims)
        {
            REQUIRE(claims->getUser() == user);
            REQUIRE_FALSE(Claims::isAdministrator(*claims));
            // The schema permissions ride in the signed token.
            Permissions permissions(claims->begin(), claims->end());
            std::ranges::sort(permissions);
            REQUIRE(permissions == Permissions {{"sandbox_utah", "read_only"},
                                                {"utah", "read_write"}});
        }
        // Not an administrator, so no hint.
        REQUIRE_FALSE(jwt::decode<jwt::traits::boost_json> (*token)
                          .get_payload_claim("administrator").as_boolean());
        REQUIRE(seeder.hasLoggedIn(user));
    }
    SECTION("An administrator's user token is a hint, not an admin token")
    {
        const auto token
            = authority.loginWithPassword(std::pair {administrator, password});
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        if (claims)
        {
            // Administration still needs the step-up.
            REQUIRE_FALSE(Claims::isAdministrator(*claims));
            // Admin does not cascade into schema access.
            REQUIRE(claims->begin() == claims->end());
        }
        REQUIRE(jwt::decode<jwt::traits::boost_json> (*token)
                    .get_payload_claim("administrator").as_boolean());
    }
    SECTION("The token carries the stored name, not the typed one")
    {
        // The login matches case-insensitively, as the SQL does.  The
        // subject must be the canonical name, or the same person is two
        // different users to everything downstream of the token.
        const auto token
            = authority.loginWithPassword(std::pair {toUpper(user), password});
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(claims.has_value());
        if (claims){REQUIRE(claims->getUser() == user);}
    }
    SECTION("Bad credentials are refused and not recorded")
    {
        auto token
            = authority.loginWithPassword(
                  std::pair {user, std::string {"green eggs"}});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);

        token = authority.loginWithPassword(
                    std::pair {"no-such-user-" + suffix, password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);

        token = authority.loginWithPassword(std::pair {std::string {},
                                                       password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);

        REQUIRE_FALSE(seeder.hasLoggedIn(user));
    }
    SECTION("verifyPassword checks without logging in")
    {
        REQUIRE(authority.verifyPassword(std::pair {user, password})
                    .has_value());
        const auto wrong
            = authority.verifyPassword(
                  std::pair {user, std::string {"green eggs"}});
        REQUIRE_FALSE(wrong.has_value());
        REQUIRE(wrong.error() == Result::InvalidCredentials);
        const auto empty
            = authority.verifyPassword(std::pair {std::string {}, password});
        REQUIRE_FALSE(empty.has_value());
        REQUIRE(empty.error() == Result::InvalidCredentials);
        REQUIRE_FALSE(seeder.hasLoggedIn(user));
    }
    SECTION("A provisional user must change the issued password first")
    {
        const auto token
            = authority.loginWithPassword(std::pair {provisional, password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::PasswordChangeRequired);
        REQUIRE_FALSE(seeder.hasLoggedIn(provisional));

        // The change is what activates the account...
        REQUIRE(authority.changePassword(std::pair {provisional, password},
                                         newPassword).has_value());
        REQUIRE(seeder.isActivated(provisional));
        REQUIRE_FALSE(seeder.isProvisional(provisional));
        // ...without counting as a login.
        REQUIRE_FALSE(seeder.hasLoggedIn(provisional));

        // Now the new password logs in and the issued one is dead.
        REQUIRE(authority.loginWithPassword(
                    std::pair {provisional, newPassword}).has_value());
        const auto old
            = authority.loginWithPassword(std::pair {provisional, password});
        REQUIRE_FALSE(old.has_value());
        REQUIRE(old.error() == Result::InvalidCredentials);
    }
    SECTION("An expired issued password does nothing")
    {
        seeder.expireProvisionalPassword(provisional);
        const auto token
            = authority.loginWithPassword(std::pair {provisional, password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);
        const auto changed
            = authority.changePassword(std::pair {provisional, password},
                                       newPassword);
        REQUIRE_FALSE(changed.has_value());
        REQUIRE(changed.error() == ChangePasswordError::Unauthenticated);
        REQUIRE_FALSE(seeder.isActivated(provisional));
    }
    SECTION("A user changes their password")
    {
        const auto before = seeder.passwordHash(user);
        REQUIRE(authority.changePassword(std::pair {user, password},
                                         newPassword).has_value());
        REQUIRE(seeder.passwordHash(user) != before);
        REQUIRE_FALSE(seeder.hasLoggedIn(user));

        REQUIRE(authority.loginWithPassword(std::pair {user, newPassword})
                    .has_value());
        const auto old
            = authority.loginWithPassword(std::pair {user, password});
        REQUIRE_FALSE(old.has_value());
        REQUIRE(old.error() == Result::InvalidCredentials);
    }
    SECTION("A password change needs the current password")
    {
        const auto before = seeder.passwordHash(user);
        auto changed
            = authority.changePassword(
                  std::pair {user, std::string {"green eggs"}}, newPassword);
        REQUIRE_FALSE(changed.has_value());
        REQUIRE(changed.error() == ChangePasswordError::Unauthenticated);

        changed = authority.changePassword(
                      std::pair {"no-such-user-" + suffix, password},
                      newPassword);
        REQUIRE_FALSE(changed.has_value());
        REQUIRE(changed.error() == ChangePasswordError::Unauthenticated);

        REQUIRE(seeder.passwordHash(user) == before);
    }
    SECTION("A password change must satisfy the policy")
    {
        const auto before = seeder.passwordHash(user);
        const auto rejected
            = [&](const std::string &proposed) -> ChangePasswordError
              {
                  const auto changed
                      = authority.changePassword(std::pair {user, password},
                                                 proposed);
                  REQUIRE_FALSE(changed.has_value());
                  return changed.error();
              };
        REQUIRE(rejected("eggs 4 ham") == ChangePasswordError::PasswordTooShort);
        REQUIRE(rejected(std::string(64, 'a') + "1")
             == ChangePasswordError::PasswordTooLong);
        REQUIRE(rejected("green eggs and spam")
             == ChangePasswordError::PasswordNeedsNumber);
        REQUIRE(rejected(password) == ChangePasswordError::PasswordsMatch);
        REQUIRE(seeder.passwordHash(user) == before);
    }
    SECTION("A login rehashes a password stored at an old cost")
    {
        // Same everything, but a higher memory cost than the seeded hash.
        auto costlier = IntegrationDatabase::cheapHasherOptions();
        costlier.setMemoryLimitInBytes(16384);
        const UserLoginAuthority rehashing{
            options(*backendCredentials, costlier),
            IntegrationDatabase::quietLogger("userLoginAuthorityTests")};
        const Password::Hasher hasher{costlier};

        const auto before = seeder.passwordHash(user);
        REQUIRE(hasher.needsRehash(before));
        REQUIRE(rehashing.loginWithPassword(std::pair {user, password})
                    .has_value());
        const auto after = seeder.passwordHash(user);
        REQUIRE(after != before);
        REQUIRE_FALSE(hasher.needsRehash(after));
        REQUIRE(Password::Hasher::verify(password, after));

        // Once is enough.
        REQUIRE(rehashing.loginWithPassword(std::pair {user, password})
                    .has_value());
        REQUIRE(seeder.passwordHash(user) == after);
    }
}
