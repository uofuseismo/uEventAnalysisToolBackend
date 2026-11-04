#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userAdministration.hpp"
#include "uEventAnalysisToolBackend/auth/userAdministrationOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "integrationDatabase.hpp"
#include "keyAssertion.hpp"
#include "userSeeder.hpp"

using namespace UEventAnalysisToolBackend::Auth;

// Integration test: user administration against a real auth schema.  The
// class under test connects as the backend role (UEAT_TEST_DB_USER) and
// acts on behalf of an actor, whom the database checks on every call.
// The outcomes are confirmed the way a user would see them - by logging
// in - or through the superuser seeder (UEAT_TEST_DB_SUPERUSER), which
// also removes every user afterwards.  Every name carries a random suffix
// so the run touches only its own rows.

namespace
{

using ReturnCode = UserAdministration::ReturnCode;
using Permission = UserAdministration::Permission;
using Result = IAuthenticator::Result;
using Permissions = std::vector<std::pair<std::string, std::string>>;

const std::string issuer{"ueat-user-administration-test"};
// What the seeder hashes.
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

[[nodiscard]] UserAdministrationOptions administrationOptions(
    const UEventAnalysisToolBackend::Database::Credentials &credentials)
{
    UserAdministrationOptions result;
    result.setDatabaseCredentials(credentials);
    result.setPasswordHasherOptions(IntegrationDatabase::cheapHasherOptions());
    result.setPasswordPolicy(policy());
    result.setIssuedPasswordTimeToLive(std::chrono::hours {1});
    return result;
}

[[nodiscard]] UserLoginAuthorityOptions loginOptions(
    const UEventAnalysisToolBackend::Database::Credentials &credentials)
{
    UserLoginAuthorityOptions result;
    result.setDatabaseCredentials(credentials);
    result.setKeyPairAndAlgorithm(
        std::pair {loadKey("ed25519-public-key.pem"),
                   loadKey("ed25519-private-key.pem")},
        UserLoginAuthorityOptions::Algorithm::EdDSA25519);
    result.setIssuer(issuer);
    result.setTimeToLive(std::chrono::minutes {15});
    result.setPasswordHasherOptions(IntegrationDatabase::cheapHasherOptions());
    result.setPasswordPolicy(policy());
    return result;
}

[[nodiscard]] std::string toUpper(std::string s)
{
    for (auto &c : s){c = static_cast<char> (std::toupper(c));}
    return s;
}

/// @result A name of exactly the given length, unique to this run.
[[nodiscard]] std::string nameOfLength(const std::size_t length,
                                       const std::string &suffix)
{
    const auto tail = "-" + suffix;
    return std::string(length - tail.size(), 'x') + tail;
}

}

TEST_CASE("UEventAnalysisToolBackend::Auth::UserAdministration",
          "[.integration][UserAdministration]")
{
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-user-administration-test-" + suffix;
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
    const std::string provisionalAdministrator{"sam-i-am-provisional-" + suffix};
    const std::string newcomer{"guy-am-i-new-" + suffix};
    const std::string stranger{"stranger-" + suffix};
    INFO("suffix = " << suffix);

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(administrator, true);
    seeder.addUser(user, false);
    seeder.addProvisionalUser(provisionalAdministrator, true);
    // Whatever the class creates, the seeder removes.  Removing a user
    // who isn't there is harmless.
    seeder.track(newcomer);

    UserAdministration administration{
        administrationOptions(*backendCredentials),
        IntegrationDatabase::quietLogger("userAdministrationTests")};
    REQUIRE(administration.isInitialized());

    UserLoginAuthority authority{
        loginOptions(*backendCredentials),
        IntegrationDatabase::quietLogger("userAdministrationTests")};
    REQUIRE(authority.isInitialized());

    TokenVerifierOptions verifierOptions;
    verifierOptions.setPublicKeyAndAlgorithm(
        loadKey("ed25519-public-key.pem"),
        TokenVerifierOptions::Algorithm::EdDSA25519);
    verifierOptions.setIssuer(issuer);
    const UserTokenVerifier verifier{
        verifierOptions,
        IntegrationDatabase::quietLogger("userAdministrationTests")};

    // What a user logging in now would be allowed to do.
    const auto permissionsOf = [&](const std::string &name) -> Permissions
    {
        const auto token
            = authority.loginWithPassword(std::pair {name, password});
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        Permissions permissions(claims->begin(), claims->end());
        std::ranges::sort(permissions);
        return permissions;
    };

    SECTION("A created user holds an issued password and must change it")
    {
        const auto issued
            = administration.createProvisionalUser(administrator, newcomer);
        REQUIRE(issued.has_value());
        REQUIRE(issued->user == newcomer);
        // The issued password is one the user could have chosen.
        REQUIRE(policy().validate(std::pair {issued->issuedPassword,
                                             std::string {}})
                == Password::PasswordPolicy::ValidationResult::Valid);
        REQUIRE(seeder.isProvisional(newcomer));
        REQUIRE_FALSE(seeder.isAdministrator(newcomer));

        const auto token = authority.loginWithPassword(
            std::pair {newcomer, issued->issuedPassword});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::PasswordChangeRequired);

        REQUIRE(authority.changePassword(
                    std::pair {newcomer, issued->issuedPassword},
                    newPassword).has_value());
        REQUIRE(authority.loginWithPassword(std::pair {newcomer, newPassword})
                    .has_value());
    }
    SECTION("Each created user gets a different password")
    {
        const auto first
            = administration.createProvisionalUser(administrator, newcomer);
        const auto second = newcomer + "-2";
        seeder.track(second);
        const auto other
            = administration.createProvisionalUser(administrator, second);
        REQUIRE(first.has_value());
        REQUIRE(other.has_value());
        REQUIRE(first->issuedPassword != other->issuedPassword);
    }
    SECTION("A created user gets the stored spelling of their name")
    {
        const auto issued = administration.createProvisionalUser(
            toUpper(administrator), "  " + toUpper(newcomer) + " ");
        REQUIRE(issued.has_value());
        REQUIRE(issued->user == newcomer);
        REQUIRE(seeder.exists(newcomer));
    }
    SECTION("A name can be created once")
    {
        REQUIRE(administration.createProvisionalUser(administrator, newcomer)
                    .has_value());
        const auto again
            = administration.createProvisionalUser(administrator,
                                                   toUpper(newcomer));
        REQUIRE_FALSE(again.has_value());
        REQUIRE(again.error() == ReturnCode::AlreadyExists);
        const auto existing
            = administration.createProvisionalUser(administrator, user);
        REQUIRE_FALSE(existing.has_value());
        REQUIRE(existing.error() == ReturnCode::AlreadyExists);
        // The existing user's password still works.
        REQUIRE(authority.loginWithPassword(std::pair {user, password})
                    .has_value());
    }
    SECTION("Names are [a-z0-9._@-], at most 64 characters")
    {
        const auto longest = nameOfLength(64, suffix);
        seeder.track(longest);
        const auto created
            = administration.createProvisionalUser(administrator, longest);
        REQUIRE(created.has_value());
        REQUIRE(seeder.exists(longest));

        const auto email = "guy.am_i-" + suffix + "@example.org";
        seeder.track(email);
        REQUIRE(administration.createProvisionalUser(administrator, email)
                    .has_value());

        for (const auto &bad : std::vector<std::string>
                 {nameOfLength(65, suffix),
                  "",
                  "   ",
                  "guy am i-" + suffix,
                  "guy;am;i-" + suffix,
                  "guy\nam\ni-" + suffix,
                  "gúy-am-i-" + suffix})
        {
            INFO("name = " << bad);
            const auto refused
                = administration.createProvisionalUser(administrator, bad);
            REQUIRE_FALSE(refused.has_value());
            REQUIRE(refused.error() == ReturnCode::InvalidArgument);
        }
        REQUIRE_FALSE(seeder.exists(nameOfLength(65, suffix)));
    }
    SECTION("A bad actor name is refused before the database is asked")
    {
        for (const auto &bad : std::vector<std::string> {"", "sam;i;am"})
        {
            INFO("actor = " << bad);
            const auto refused
                = administration.createProvisionalUser(bad, newcomer);
            REQUIRE_FALSE(refused.has_value());
            REQUIRE(refused.error() == ReturnCode::InvalidArgument);
            REQUIRE(administration.removeUser(bad, user)
                    == ReturnCode::InvalidArgument);
        }
        REQUIRE_FALSE(seeder.exists(newcomer));
    }
    SECTION("Only an activated administrator may act")
    {
        // A user, an administrator who hasn't changed their issued
        // password, and nobody at all.
        for (const auto &actor :
             std::vector<std::string> {user, provisionalAdministrator,
                                       stranger})
        {
            INFO("actor = " << actor);
            const auto created
                = administration.createProvisionalUser(actor, newcomer);
            REQUIRE_FALSE(created.has_value());
            REQUIRE(created.error() == ReturnCode::NotAuthorized);
            const auto reset = administration.resetPassword(actor, user, false);
            REQUIRE_FALSE(reset.has_value());
            REQUIRE(reset.error() == ReturnCode::NotAuthorized);
            REQUIRE(administration.removeUser(actor, user)
                    == ReturnCode::NotAuthorized);
            REQUIRE(administration.setPermission(actor, user, "ynp",
                                                 Permission::ReadWrite)
                    == ReturnCode::NotAuthorized);
            REQUIRE(administration.revokePermission(actor, user, "ynp")
                    == ReturnCode::NotAuthorized);
            REQUIRE(administration.setAdministrator(actor, actor)
                    == ReturnCode::NotAuthorized);
            REQUIRE(administration.revokeAdministrator(actor, administrator)
                    == ReturnCode::NotAuthorized);
            // Not even a schema that doesn't exist gets past the actor:
            // a non-administrator learns nothing about the schemas.
            REQUIRE(administration.setPermission(actor, user, "atlantis",
                                                 Permission::ReadOnly)
                    == ReturnCode::NotAuthorized);
        }
        // Nothing happened.
        REQUIRE_FALSE(seeder.exists(newcomer));
        REQUIRE_FALSE(seeder.isProvisional(user));
        REQUIRE(seeder.isAdministrator(administrator));
        REQUIRE_FALSE(seeder.isAdministrator(user));
        REQUIRE(permissionsOf(user).empty());
    }
    SECTION("A demoted administrator loses the power at once")
    {
        // The database asks the users table, not the token, so this
        // holds even while the demoted administrator's token is valid.
        const auto deputy = "sam-i-am-deputy-" + suffix;
        seeder.addUser(deputy, true);
        REQUIRE(administration.revokeAdministrator(administrator, deputy)
                == ReturnCode::Success);
        const auto created
            = administration.createProvisionalUser(deputy, newcomer);
        REQUIRE_FALSE(created.has_value());
        REQUIRE(created.error() == ReturnCode::NotAuthorized);
    }
    SECTION("Permissions set and revoked are what the next login carries")
    {
        REQUIRE(administration.setPermission(administrator, user, "utah",
                                             Permission::ReadOnly)
                == ReturnCode::Success);
        REQUIRE(administration.setPermission(administrator, user,
                                             " SANDBOX_UTAH ",
                                             Permission::ReadWrite)
                == ReturnCode::Success);
        REQUIRE(permissionsOf(user)
                == Permissions {{"sandbox_utah", "read_write"},
                                {"utah", "read_only"}});

        // Setting again changes the level rather than adding a row.
        REQUIRE(administration.setPermission(administrator, user, "utah",
                                             Permission::ReadWrite)
                == ReturnCode::Success);
        REQUIRE(permissionsOf(user)
                == Permissions {{"sandbox_utah", "read_write"},
                                {"utah", "read_write"}});

        REQUIRE(administration.revokePermission(administrator, user,
                                                "sandbox_utah")
                == ReturnCode::Success);
        REQUIRE(permissionsOf(user)
                == Permissions {{"utah", "read_write"}});
        // Nothing left to revoke.
        REQUIRE(administration.revokePermission(administrator, user,
                                                "sandbox_utah")
                == ReturnCode::NoUserFound);
    }
    SECTION("Permissions need a real user and a real schema")
    {
        REQUIRE(administration.setPermission(administrator, stranger, "utah",
                                             Permission::ReadOnly)
                == ReturnCode::NoUserFound);
        REQUIRE(administration.revokePermission(administrator, stranger,
                                                "utah")
                == ReturnCode::NoUserFound);
        // One the database doesn't know, and ones that can't be a schema
        // at all.
        for (const auto &schema :
             std::vector<std::string> {"atlantis", "", "utah;drop",
                                       "utah\nok", std::string(64, 'u')})
        {
            INFO("schema = " << schema);
            REQUIRE(administration.setPermission(administrator, user, schema,
                                                 Permission::ReadOnly)
                    == ReturnCode::NoSchema);
            REQUIRE(administration.revokePermission(administrator, user,
                                                    schema)
                    == ReturnCode::NoSchema);
        }
        REQUIRE(permissionsOf(user).empty());
    }
    SECTION("Administrator is set and revoked")
    {
        REQUIRE(administration.setAdministrator(administrator, user)
                == ReturnCode::Success);
        REQUIRE(seeder.isAdministrator(user));
        // The new administrator can act...
        REQUIRE(administration.createProvisionalUser(user, newcomer)
                    .has_value());
        // ...and confers no schema access on themselves.
        REQUIRE(permissionsOf(user).empty());

        REQUIRE(administration.revokeAdministrator(administrator, user)
                == ReturnCode::Success);
        REQUIRE_FALSE(seeder.isAdministrator(user));

        REQUIRE(administration.setAdministrator(administrator, stranger)
                == ReturnCode::NoUserFound);
        REQUIRE(administration.revokeAdministrator(administrator, stranger)
                == ReturnCode::NoUserFound);
    }
    SECTION("A removed user is gone")
    {
        REQUIRE(administration.removeUser(administrator, toUpper(user))
                == ReturnCode::Success);
        REQUIRE_FALSE(seeder.exists(user));
        const auto token
            = authority.loginWithPassword(std::pair {user, password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);

        REQUIRE(administration.removeUser(administrator, user)
                == ReturnCode::NoUserFound);
    }
    SECTION("A reset issues a new password and kills the old one")
    {
        const IntegrationDatabase::KeyPair key;
        seeder.addKey(user, "laptop", key.encodedPublicKey());

        const auto issued
            = administration.resetPassword(administrator, user, false);
        REQUIRE(issued.has_value());
        REQUIRE(issued->user == user);
        REQUIRE(seeder.isProvisional(user));
        // A reset of an established user does not undo their activation.
        REQUIRE(seeder.isActivated(user));
        // An ordinary reset - the user forgot - leaves their keys alone.
        REQUIRE_FALSE(seeder.keyIsRevoked(user, "laptop"));

        const auto old
            = authority.loginWithPassword(std::pair {user, password});
        REQUIRE_FALSE(old.has_value());
        REQUIRE(old.error() == Result::InvalidCredentials);
        const auto token = authority.loginWithPassword(
            std::pair {user, issued->issuedPassword});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::PasswordChangeRequired);

        const auto nobody
            = administration.resetPassword(administrator, stranger, false);
        REQUIRE_FALSE(nobody.has_value());
        REQUIRE(nobody.error() == ReturnCode::NoUserFound);
    }
    SECTION("A compromise reset also revokes the user's keys")
    {
        const IntegrationDatabase::KeyPair key;
        seeder.addKey(user, "laptop", key.encodedPublicKey());

        const auto issued
            = administration.resetPassword(administrator, user, true);
        REQUIRE(issued.has_value());
        REQUIRE(seeder.keyIsRevoked(user, "laptop"));
        const auto old
            = authority.loginWithPassword(std::pair {user, password});
        REQUIRE_FALSE(old.has_value());
        REQUIRE(old.error() == Result::InvalidCredentials);
    }
    SECTION("The last administrator cannot be removed, demoted, or reset")
    {
        // Only meaningful if this run's administrator is the only one.
        // A fresh test database has no other; a leftover from an
        // aborted run, or a real bootstrap administrator, means skip.
        if (seeder.countActiveAdministrators() != 1)
        {
            SKIP("Another administrator exists, so "
                 << administrator << " is not the last one");
        }
        REQUIRE(administration.removeUser(administrator, administrator)
                == ReturnCode::LastAdministrator);
        REQUIRE(administration.revokeAdministrator(administrator,
                                                   administrator)
                == ReturnCode::LastAdministrator);
        for (const bool revokeKeys : {false, true})
        {
            const auto reset = administration.resetPassword(
                administrator, administrator, revokeKeys);
            REQUIRE_FALSE(reset.has_value());
            REQUIRE(reset.error() == ReturnCode::LastAdministrator);
        }
        // Still there, still in charge, password unchanged.
        REQUIRE(seeder.isAdministrator(administrator));
        REQUIRE_FALSE(seeder.isProvisional(administrator));
        REQUIRE(authority.loginWithPassword(
                    std::pair {administrator, password}).has_value());

        // With a second administrator the same calls are allowed.
        const auto deputy = "sam-i-am-deputy-" + suffix;
        seeder.addUser(deputy, true);
        REQUIRE(administration.revokeAdministrator(administrator,
                                                   administrator)
                == ReturnCode::Success);
        REQUIRE_FALSE(seeder.isAdministrator(administrator));
    }
}
