#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/utils.h>
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userAdministration.hpp"
#include "uEventAnalysisToolBackend/auth/userAdministrationOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userList.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include <uEventAnalysisToolAPI/admin/v1/list_users_response.pb.h>
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
            REQUIRE(administration.deleteUser(bad, user)
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
            REQUIRE(administration.deleteUser(actor, user)
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
            // Nor may they see who else is here.
            const auto listed = administration.listUsers(actor);
            REQUIRE_FALSE(listed.has_value());
            REQUIRE(listed.error() == ReturnCode::NotAuthorized);
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
        REQUIRE(administration.deleteUser(administrator, toUpper(user))
                == ReturnCode::Success);
        REQUIRE_FALSE(seeder.exists(user));
        const auto token
            = authority.loginWithPassword(std::pair {user, password});
        REQUIRE_FALSE(token.has_value());
        REQUIRE(token.error() == Result::InvalidCredentials);

        REQUIRE(administration.deleteUser(administrator, user)
                == ReturnCode::NoUserFound);
    }
    SECTION("The database fingerprints a key the way a client would")
    {
        // The recipe the ListUsersResponse documents for clients:
        // SHA-256 of the raw 32 key bytes, standard base64, no padding.
        const IntegrationDatabase::KeyPair key;
        seeder.addKey(user, "laptop", key.encodedPublicKey());
        const auto publicKey = key.publicKey();
        std::array<unsigned char, crypto_hash_sha256_BYTES> digest {};
        crypto_hash_sha256(digest.data(), publicKey.data(), publicKey.size());
        const auto expected
            = "SHA256:"
            + IntegrationDatabase::toBase64(
                  digest.data(), digest.size(),
                  sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
        REQUIRE(seeder.keyFingerprint(user, "laptop") == expected);
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
    SECTION("An administrator lists every user, split by state")
    {
        // One of each: an active user with grants, a login, and keys in
        // every state; a reset user; a provisional administrator; and a
        // newcomer whose issued password lapses.
        const auto reset = "guy-am-i-reset-" + suffix;
        seeder.addUser(reset, false);
        seeder.setPermission(user, "ynp", "read_only");
        seeder.setPermission(user, "utah", "read_write");
        const IntegrationDatabase::KeyPair laptop;
        const IntegrationDatabase::KeyPair old;
        const IntegrationDatabase::KeyPair dated;
        seeder.addKey(user, "laptop", laptop.encodedPublicKey(), 3600);
        seeder.addKey(user, "old", old.encodedPublicKey());
        seeder.revokeKey(user, "old");
        seeder.addKey(user, "dated", dated.encodedPublicKey(), 1);
        REQUIRE(administration.createProvisionalUser(administrator, newcomer)
                              .has_value());
        REQUIRE(administration.resetPassword(administrator, reset, false)
                              .has_value());
        REQUIRE_FALSE(permissionsOf(user).empty());   // logs user in
        // Long enough for dated to expire, and for the newcomer's lapsed
        // deadline below to fall after the account was created.
        std::this_thread::sleep_for(std::chrono::milliseconds {1100});
        seeder.expireProvisionalPassword(newcomer);

        const auto listed = administration.listUsers(toUpper(administrator));
        REQUIRE(listed.has_value());
        const auto &active = listed->getActiveUsersReference();
        const auto &provisional = listed->getProvisionalUsersReference();
        const auto findIn = [](const auto &users, const std::string &name)
        {
            return std::ranges::find_if(users, [&](const auto &u)
                                        {
                                            return u.getName() == name;
                                        });
        };

        // Which list each lands in, and only that one.
        for (const auto &name : {administrator, user})
        {
            INFO("name = " << name);
            REQUIRE(findIn(active, name) != active.end());
            REQUIRE(findIn(provisional, name) == provisional.end());
        }
        for (const auto &name : {provisionalAdministrator, newcomer, reset})
        {
            INFO("name = " << name);
            REQUIRE(findIn(provisional, name) != provisional.end());
            REQUIRE(findIn(active, name) == active.end());
        }
        REQUIRE(findIn(active, stranger) == active.end());
        REQUIRE(findIn(provisional, stranger) == provisional.end());
        // Sorted by name, as the database returns them.
        REQUIRE(std::ranges::is_sorted(active, {}, &ActiveUser::getName));
        REQUIRE(std::ranges::is_sorted(provisional, {},
                                       &ProvisionalUser::getName));

        const auto &admin = *findIn(active, administrator);
        REQUIRE(admin.isAdministrator());
        REQUIRE_FALSE(admin.getLastLogin().has_value());
        REQUIRE(admin.getWhenPasswordUpdated() >= admin.getWhenCreated());
        REQUIRE(admin.getSchemaPermissions().empty());
        REQUIRE(admin.getActiveKeys().empty());
        REQUIRE(admin.getInactiveKeys().empty());

        const auto &guy = *findIn(active, user);
        REQUIRE_FALSE(guy.isAdministrator());
        const auto lastLogin = guy.getLastLogin();
        REQUIRE(lastLogin.has_value());
        REQUIRE(lastLogin.value_or(std::chrono::microseconds {0})
                >= guy.getWhenCreated());

        const auto permissions = guy.getSchemaPermissions();
        REQUIRE(permissions.size() == 2);
        REQUIRE(permissions.at(0).getSchema() == "utah");
        REQUIRE(permissions.at(0).getPermission()
                == SchemaPermission::Permission::ReadWrite);
        REQUIRE(permissions.at(1).getSchema() == "ynp");
        REQUIRE(permissions.at(1).getPermission()
                == SchemaPermission::Permission::ReadOnly);
        for (const auto &permission : permissions)
        {
            REQUIRE(permission.getWhenGranted() >= guy.getWhenCreated());
        }

        const auto activeKeys = guy.getActiveKeys();
        REQUIRE(activeKeys.size() == 1);
        REQUIRE(activeKeys.at(0).getName() == "laptop");
        REQUIRE(activeKeys.at(0).getAlgorithm() == ActiveKey::Algorithm::ed25519);
        REQUIRE(activeKeys.at(0).getFingerprint()
                == seeder.keyFingerprint(user, "laptop"));
        const auto expiration = activeKeys.at(0).getExpiration();
        REQUIRE(expiration.has_value());
        REQUIRE(expiration.value_or(std::chrono::microseconds {0})
                > activeKeys.at(0).getWhenRegistered());
        REQUIRE_FALSE(activeKeys.at(0).getLastUsed().has_value());

        auto inactiveKeys = guy.getInactiveKeys();
        REQUIRE(inactiveKeys.size() == 2);
        std::ranges::sort(inactiveKeys, {}, &InactiveKey::getName);
        const auto &datedKey = inactiveKeys.at(0);
        const auto &oldKey = inactiveKeys.at(1);
        REQUIRE(datedKey.getName() == "dated");
        REQUIRE(datedKey.getReason() == InactiveKey::Reason::Expired);
        REQUIRE(datedKey.getFingerprint() == seeder.keyFingerprint(user, "dated"));
        REQUIRE(datedKey.getWhenInvalidated() > datedKey.getWhenRegistered());
        REQUIRE(oldKey.getName() == "old");
        REQUIRE(oldKey.getReason() == InactiveKey::Reason::Revoked);
        REQUIRE(oldKey.getWhenInvalidated() >= oldKey.getWhenRegistered());
        REQUIRE(datedKey.getFingerprint() != oldKey.getFingerprint());

        const auto &pending = *findIn(provisional, provisionalAdministrator);
        REQUIRE(pending.isAdministrator());
        REQUIRE_FALSE(pending.isExpired());
        REQUIRE_FALSE(pending.passwordReset());
        REQUIRE(pending.getExpiration() > pending.getWhenCreated());

        const auto &lapsed = *findIn(provisional, newcomer);
        REQUIRE_FALSE(lapsed.isAdministrator());
        REQUIRE(lapsed.isExpired());
        REQUIRE_FALSE(lapsed.passwordReset());

        const auto &wasReset = *findIn(provisional, reset);
        REQUIRE_FALSE(wasReset.isExpired());
        REQUIRE(wasReset.passwordReset());

        // What goes on the wire: unset stays unset rather than reading
        // as 1970.
        namespace V1 = UEventAnalysisToolAPI::Admin::V1;
        const auto adminMessage
            = admin.toMessage<V1::ListUsersResponse::ActiveUser> ();
        REQUIRE(adminMessage.has_created());
        REQUIRE(adminMessage.has_password_updated());
        REQUIRE_FALSE(adminMessage.has_last_login());
        const auto guyMessage
            = guy.toMessage<V1::ListUsersResponse::ActiveUser> ();
        REQUIRE(guyMessage.has_last_login());
        REQUIRE(guyMessage.permissions_size() == 2);
        REQUIRE(guyMessage.active_keys_size() == 1);
        REQUIRE(guyMessage.active_keys(0).has_expires());
        REQUIRE_FALSE(guyMessage.active_keys(0).has_last_used());
        REQUIRE(guyMessage.inactive_keys_size() == 2);
        for (const auto &key : guyMessage.inactive_keys())
        {
            REQUIRE(key.has_invalidated());
            REQUIRE(key.reason()
                    != V1::ListUsersResponse::InactiveKey::REASON_NOT_SPECIFIED);
        }
        const auto lapsedMessage
            = lapsed.toMessage<V1::ListUsersResponse::ProvisionalUser> ();
        REQUIRE(lapsedMessage.has_expiration());
        REQUIRE(lapsedMessage.expired());
        REQUIRE_FALSE(lapsedMessage.has_last_login());
    }
    SECTION("Listing needs a valid actor")
    {
        for (const auto &actor : {std::string {}, std::string {"b o b"}})
        {
            const auto listed = administration.listUsers(actor);
            REQUIRE_FALSE(listed.has_value());
            REQUIRE(listed.error() == ReturnCode::InvalidArgument);
        }
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
        REQUIRE(administration.deleteUser(administrator, administrator)
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
