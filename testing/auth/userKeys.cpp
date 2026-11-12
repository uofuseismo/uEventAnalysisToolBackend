#include <cctype>
#include <chrono>
#include <expected>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <boost/json/object.hpp>
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "integrationDatabase.hpp"
#include "keyAssertion.hpp"
#include "userSeeder.hpp"

using namespace UEventAnalysisToolBackend::Auth;

// Integration test: a user registering and revoking their own login keys
// against a real auth schema.  As in userLoginAuthority.cpp, the authority
// connects as the backend role and the users are seeded, and removed, by
// a superuser.  Keys the authority adds go when their user does.

namespace
{

using KeyError = UserLoginAuthority::KeyError;

const std::string issuer{"ueat-user-keys-test"};
// The audience an add-key assertion must name.  A login assertion names
// the bare issuer, so neither can stand in for the other.
const std::string keysAudience{issuer + "/keys"};
const std::string password{"green eggs and ham"};
// Small, so the cap is reachable in a test.
constexpr int maximumKeys{3};
const std::chrono::seconds maximumLifetime{std::chrono::days {2}};

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

[[nodiscard]] UserLoginAuthorityOptions options(
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
    result.setPasswordPolicy(Password::PasswordPolicy {});
    result.setMaximumNumberOfLoginKeys(maximumKeys);
    result.setMaximumLoginKeyTimeToLive(maximumLifetime);
    return result;
}

/// @result What a client sends to prove it holds the key it is adding.
[[nodiscard]] std::string addKeyAssertion(
    const IntegrationDatabase::KeyPair &key, const std::string &subject)
{
    return key.sign(IntegrationDatabase::assertionHeader(),
                    IntegrationDatabase::assertionPayload(subject,
                                                          keysAudience));
}

/// @result What a client sends to log in with the key.
[[nodiscard]] std::string loginAssertion(
    const IntegrationDatabase::KeyPair &key, const std::string &subject)
{
    return key.sign(IntegrationDatabase::assertionHeader(),
                    IntegrationDatabase::assertionPayload(subject, issuer));
}

[[nodiscard]] std::string toUpper(std::string s)
{
    for (auto &c : s){c = static_cast<char> (std::toupper(c));}
    return s;
}

}

TEST_CASE("UEventAnalysisToolBackend::Auth::UserLoginAuthority::addKey",
          "[.integration][UserLoginAuthority]")
{
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-user-keys-test-" + suffix;
    const auto backendCredentials
        = IntegrationDatabase::credentials(application);
    const auto superuserCredentials
        = IntegrationDatabase::superuserCredentials(application + "-seeder");
    if (!backendCredentials || !superuserCredentials)
    {
        SKIP("Set UEAT_TEST_DB_{HOST,PORT,NAME,USER,PASSWORD} and "
             "UEAT_TEST_DB_SUPERUSER{,_PASSWORD} to run this");
    }

    const std::string user{"guy-am-i-" + suffix};
    const std::string other{"sam-i-am-" + suffix};
    const std::string newcomer{"i-am-sam-" + suffix};
    INFO("suffix = " << suffix);

    // user already holds laptop; other holds theirs.  newcomer still has
    // the password an administrator issued.
    const IntegrationDatabase::KeyPair laptop;
    const IntegrationDatabase::KeyPair theirs;
    const IntegrationDatabase::KeyPair desktop;
    const IntegrationDatabase::KeyPair stranger;

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(user, false);
    seeder.addKey(user, "laptop", laptop.encodedPublicKey());
    seeder.addUser(other, false);
    seeder.addKey(other, "theirs", theirs.encodedPublicKey());
    seeder.addProvisionalUser(newcomer);

    UserLoginAuthority authority{
        options(*backendCredentials),
        IntegrationDatabase::quietLogger("userKeysTests")};
    REQUIRE(authority.isInitialized());

    const std::pair credentials{user, password};
    // Adds desktop for user, as a well-behaved client would, but with
    // any one piece swapped out.
    const auto add = [&](const std::string &keyName,
                         const std::optional<std::chrono::seconds> &expiresAfter
                             = std::nullopt)
    {
        return authority.addKey(credentials, keyName, desktop.publicKey(),
                                addKeyAssertion(desktop, user), expiresAfter);
    };
    const auto refusedWith = [](const std::expected<void, KeyError> &result,
                                const KeyError expected)
    {
        return !result.has_value() && result.error() == expected;
    };

    SECTION("A user adds a key and logs in with it")
    {
        REQUIRE(add("desktop").has_value());
        REQUIRE(seeder.hasKey(user, "desktop"));
        REQUIRE(authority.loginWithKey(desktop.publicKey(),
                                       loginAssertion(desktop, user))
                    .has_value());
        REQUIRE(seeder.keyHasBeenUsed(user, "desktop"));
    }
    SECTION("The key name is stored the way the database spells it")
    {
        REQUIRE(add(" Work-Laptop ").has_value());
        REQUIRE(seeder.hasKey(user, "work-laptop"));
    }
    SECTION("The user name may be typed in any case")
    {
        const std::pair shouted{toUpper(user), password};
        REQUIRE(authority.addKey(shouted, "desktop", desktop.publicKey(),
                                 addKeyAssertion(desktop, toUpper(user)),
                                 std::nullopt).has_value());
        REQUIRE(seeder.hasKey(user, "desktop"));
    }
    SECTION("An unset expiration is the configured maximum")
    {
        // A key that never expires would sidestep the cap.
        REQUIRE(add("desktop").has_value());
        const auto expiresIn = seeder.keyExpiresIn(user, "desktop");
        REQUIRE(expiresIn.has_value());
        const auto lifetime = expiresIn.value_or(std::chrono::seconds {0});
        REQUIRE(lifetime > maximumLifetime - std::chrono::minutes {1});
        REQUIRE(lifetime <= maximumLifetime);
    }
    SECTION("A requested expiration is kept")
    {
        REQUIRE(add("desktop", std::chrono::hours {1}).has_value());
        const auto lifetime = seeder.keyExpiresIn(user, "desktop")
                                    .value_or(std::chrono::seconds {0});
        REQUIRE(lifetime > std::chrono::minutes {59});
        REQUIRE(lifetime <= std::chrono::hours {1});
    }
    SECTION("The expiration must be positive and within the maximum")
    {
        REQUIRE(refusedWith(add("desktop", std::chrono::seconds {0}),
                            KeyError::InvalidExpiration));
        REQUIRE(refusedWith(add("desktop", std::chrono::seconds {-60}),
                            KeyError::InvalidExpiration));
        REQUIRE(refusedWith(add("desktop",
                                maximumLifetime + std::chrono::seconds {1}),
                            KeyError::InvalidExpiration));
        // Exactly the maximum is allowed.
        REQUIRE(add("desktop", maximumLifetime).has_value());
    }
    SECTION("Adding a key needs the current password")
    {
        REQUIRE(refusedWith(
            authority.addKey({user, "wrong password"}, "desktop",
                             desktop.publicKey(),
                             addKeyAssertion(desktop, user), std::nullopt),
            KeyError::Unauthenticated));
        const auto nobody = "nobody-" + suffix;
        REQUIRE(refusedWith(
            authority.addKey({nobody, password}, "desktop",
                             desktop.publicKey(),
                             addKeyAssertion(desktop, nobody), std::nullopt),
            KeyError::Unauthenticated));
        REQUIRE(refusedWith(
            authority.addKey({"", password}, "desktop", desktop.publicKey(),
                             addKeyAssertion(desktop, user), std::nullopt),
            KeyError::Unauthenticated));
        REQUIRE_FALSE(seeder.hasKey(user, "desktop"));
    }
    SECTION("An issued password cannot add a key")
    {
        // The password is right, but a key would outlive it.
        REQUIRE(refusedWith(
            authority.addKey({newcomer, password}, "desktop",
                             desktop.publicKey(),
                             addKeyAssertion(desktop, newcomer), std::nullopt),
            KeyError::PasswordChangeRequired));
        REQUIRE_FALSE(seeder.hasKey(newcomer, "desktop"));
    }
    SECTION("The caller must prove they hold the key")
    {
        const auto attempt = [&](const std::vector<unsigned char> &publicKey,
                                 const std::string &assertion)
        {
            return authority.addKey(credentials, "desktop", publicKey,
                                    assertion, std::nullopt);
        };
        // Signed by a key other than the one being added: e.g., someone
        // registering a public key they copied from elsewhere.
        REQUIRE(refusedWith(attempt(desktop.publicKey(),
                                    addKeyAssertion(stranger, user)),
                            KeyError::InvalidKey));
        // A login assertion is not an add-key assertion.
        REQUIRE(refusedWith(attempt(desktop.publicKey(),
                                    loginAssertion(desktop, user)),
                            KeyError::InvalidKey));
        // Signed for someone else.
        REQUIRE(refusedWith(attempt(desktop.publicKey(),
                                    addKeyAssertion(desktop, other)),
                            KeyError::InvalidKey));
        // Expired.
        auto payload
            = IntegrationDatabase::assertionPayload(user, keysAudience);
        const auto now = payload.at("iat").as_int64();
        payload["iat"] = now - 120;
        payload["exp"] = now - 60;
        REQUIRE(refusedWith(attempt(desktop.publicKey(),
                                    desktop.sign(
                                        IntegrationDatabase::assertionHeader(),
                                        payload)),
                            KeyError::InvalidKey));
        // Not a 32-byte key.
        auto shortKey = desktop.publicKey();
        shortKey.pop_back();
        REQUIRE(refusedWith(attempt(shortKey, addKeyAssertion(desktop, user)),
                            KeyError::InvalidKey));
        REQUIRE(refusedWith(attempt({}, addKeyAssertion(desktop, user)),
                            KeyError::InvalidKey));
        REQUIRE(refusedWith(attempt(desktop.publicKey(), "not.a.jws"),
                            KeyError::InvalidKey));
        REQUIRE_FALSE(seeder.hasKey(user, "desktop"));
    }
    SECTION("An add-key assertion does not log in")
    {
        const auto assertion = addKeyAssertion(desktop, user);
        REQUIRE(authority.addKey(credentials, "desktop", desktop.publicKey(),
                                 assertion, std::nullopt).has_value());
        REQUIRE_FALSE(authority.loginWithKey(desktop.publicKey(), assertion)
                          .has_value());
        REQUIRE_FALSE(seeder.keyHasBeenUsed(user, "desktop"));
    }
    SECTION("A bad key name is refused as a bad name")
    {
        REQUIRE(refusedWith(add("my laptop"), KeyError::InvalidName));
        REQUIRE(refusedWith(add(""), KeyError::InvalidName));
        REQUIRE(refusedWith(add(std::string(65, 'k')), KeyError::InvalidName));
        REQUIRE(add(std::string(64, 'k')).has_value());
    }
    SECTION("A clash is reported as itself")
    {
        // user already has a laptop.
        REQUIRE(refusedWith(add("laptop"), KeyError::NameInUse));
        REQUIRE(refusedWith(add("LAPTOP"), KeyError::NameInUse));
        // The same key under a second name.
        REQUIRE(refusedWith(
            authority.addKey(credentials, "laptop-again", laptop.publicKey(),
                             addKeyAssertion(laptop, user), std::nullopt),
            KeyError::KeyInUse));
        // Someone else's key - only reachable by its holder, given the
        // proof of possession.
        REQUIRE(refusedWith(
            authority.addKey(credentials, "borrowed", theirs.publicKey(),
                             addKeyAssertion(theirs, user), std::nullopt),
            KeyError::KeyInUse));
        // A revoked key keeps its name.
        seeder.revokeKey(user, "laptop");
        REQUIRE(refusedWith(add("laptop"), KeyError::NameInUse));
    }
    SECTION("The number of active keys is capped")
    {
        // laptop plus two more is the cap.
        const IntegrationDatabase::KeyPair second;
        const IntegrationDatabase::KeyPair third;
        REQUIRE(authority.addKey(credentials, "second", second.publicKey(),
                                 addKeyAssertion(second, user), std::nullopt)
                    .has_value());
        REQUIRE(authority.addKey(credentials, "third", third.publicKey(),
                                 addKeyAssertion(third, user), std::nullopt)
                    .has_value());
        REQUIRE(refusedWith(add("desktop"), KeyError::TooManyKeys));
        REQUIRE_FALSE(seeder.hasKey(user, "desktop"));
        // Revoking makes room.
        REQUIRE(authority.revokeKey(user, "second").has_value());
        REQUIRE(add("desktop").has_value());
        // The cap is per user.
        const IntegrationDatabase::KeyPair othersSecond;
        REQUIRE(authority.addKey({other, password}, "second",
                                 othersSecond.publicKey(),
                                 addKeyAssertion(othersSecond, other),
                                 std::nullopt).has_value());
    }
}

TEST_CASE("UEventAnalysisToolBackend::Auth::UserLoginAuthority::revokeKey",
          "[.integration][UserLoginAuthority]")
{
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-user-keys-revoke-test-" + suffix;
    const auto backendCredentials
        = IntegrationDatabase::credentials(application);
    const auto superuserCredentials
        = IntegrationDatabase::superuserCredentials(application + "-seeder");
    if (!backendCredentials || !superuserCredentials)
    {
        SKIP("Set UEAT_TEST_DB_{HOST,PORT,NAME,USER,PASSWORD} and "
             "UEAT_TEST_DB_SUPERUSER{,_PASSWORD} to run this");
    }

    const std::string user{"guy-am-i-" + suffix};
    const std::string other{"sam-i-am-" + suffix};
    INFO("suffix = " << suffix);

    const IntegrationDatabase::KeyPair laptop;
    const IntegrationDatabase::KeyPair desktop;
    const IntegrationDatabase::KeyPair theirs;

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(user, false);
    seeder.addKey(user, "laptop", laptop.encodedPublicKey());
    seeder.addKey(user, "desktop", desktop.encodedPublicKey());
    seeder.addUser(other, false);
    seeder.addKey(other, "theirs", theirs.encodedPublicKey());

    UserLoginAuthority authority{
        options(*backendCredentials),
        IntegrationDatabase::quietLogger("userKeysTests")};
    REQUIRE(authority.isInitialized());

    const auto refusedWith = [](const std::expected<void, KeyError> &result,
                                const KeyError expected)
    {
        return !result.has_value() && result.error() == expected;
    };
    const auto logsIn = [&](const IntegrationDatabase::KeyPair &key,
                            const std::string &subject)
    {
        return authority.loginWithKey(key.publicKey(),
                                      loginAssertion(key, subject))
                   .has_value();
    };

    SECTION("A revoked key stops working; the others do not")
    {
        REQUIRE(logsIn(laptop, user));
        REQUIRE(authority.revokeKey(user, "laptop").has_value());
        REQUIRE(seeder.keyIsRevoked(user, "laptop"));
        REQUIRE_FALSE(logsIn(laptop, user));
        REQUIRE(logsIn(desktop, user));
    }
    SECTION("Names are matched in any case")
    {
        REQUIRE(authority.revokeKey(toUpper(user), " LAPTOP ").has_value());
        REQUIRE(seeder.keyIsRevoked(user, "laptop"));
    }
    SECTION("Only an active key of the user's own is revoked")
    {
        REQUIRE(authority.revokeKey(user, "laptop").has_value());
        REQUIRE(refusedWith(authority.revokeKey(user, "laptop"),
                            KeyError::NoKeyFound));
        REQUIRE(refusedWith(authority.revokeKey(user, "tablet"),
                            KeyError::NoKeyFound));
        REQUIRE(refusedWith(authority.revokeKey(user, ""),
                            KeyError::NoKeyFound));
        // other's key, named by user: not user's to revoke.
        REQUIRE(refusedWith(authority.revokeKey(user, "theirs"),
                            KeyError::NoKeyFound));
        REQUIRE_FALSE(seeder.keyIsRevoked(other, "theirs"));
        REQUIRE(logsIn(theirs, other));
    }
    SECTION("Revoking needs a user who exists")
    {
        REQUIRE(refusedWith(authority.revokeKey("nobody-" + suffix, "laptop"),
                            KeyError::Unauthenticated));
        REQUIRE(refusedWith(authority.revokeKey("", "laptop"),
                            KeyError::Unauthenticated));
        REQUIRE_FALSE(seeder.keyIsRevoked(user, "laptop"));
    }
}
