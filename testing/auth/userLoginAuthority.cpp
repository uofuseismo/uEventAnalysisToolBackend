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
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
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
#include "keyAssertion.hpp"
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

TEST_CASE("UEventAnalysisToolBackend::Auth::UserLoginAuthority::loginWithKey",
          "[.integration][UserLoginAuthority]")
{
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-key-login-test-" + suffix;
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

    // user holds laptop and an already-revoked old key; other holds one
    // of their own.  stranger is registered to nobody.
    const IntegrationDatabase::KeyPair laptop;
    const IntegrationDatabase::KeyPair old;
    const IntegrationDatabase::KeyPair othersKey;
    const IntegrationDatabase::KeyPair stranger;

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(user, false);
    seeder.setPermission(user, "utah", "read_write");
    seeder.addKey(user, "laptop", laptop.encodedPublicKey());
    seeder.addKey(user, "old", old.encodedPublicKey());
    seeder.revokeKey(user, "old");
    seeder.addUser(other, false);
    seeder.addKey(other, "laptop", othersKey.encodedPublicKey());

    const UserLoginAuthority authority{
        options(*backendCredentials, IntegrationDatabase::cheapHasherOptions()),
        IntegrationDatabase::quietLogger("userKeyLoginTests")};
    REQUIRE(authority.isInitialized());

    TokenVerifierOptions verifierOptions;
    verifierOptions.setPublicKeyAndAlgorithm(
        loadKey("ed25519-public-key.pem"),
        TokenVerifierOptions::Algorithm::EdDSA25519);
    verifierOptions.setIssuer(issuer);
    const UserTokenVerifier verifier{
        verifierOptions,
        IntegrationDatabase::quietLogger("userKeyLoginTests")};

    const auto header = IntegrationDatabase::assertionHeader();
    auto payload = IntegrationDatabase::assertionPayload(user, issuer);
    const auto now = payload.at("iat").as_int64();
    // Every refusal must be InvalidCredentials: bad client input is never
    // a server error.
    const auto refused = [&](const std::vector<unsigned char> &publicKey,
                             const std::string &assertion)
    {
        const auto token = authority.loginWithKey(publicKey, assertion);
        return !token.has_value() &&
               token.error() == Result::InvalidCredentials;
    };

    SECTION("A signed assertion gets a user token")
    {
        const auto token
            = authority.loginWithKey(laptop.publicKey(),
                                     laptop.sign(header, payload));
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        if (claims)
        {
            REQUIRE(claims->getUser() == user);
            REQUIRE_FALSE(Claims::isAdministrator(*claims));
            const Permissions permissions(claims->begin(), claims->end());
            REQUIRE(permissions == Permissions {{"utah", "read_write"}});
        }
        // record_key_use stamps both.
        REQUIRE(seeder.keyHasBeenUsed(user, "laptop"));
        REQUIRE(seeder.hasLoggedIn(user));
    }
    SECTION("An assertion logs in once")
    {
        const auto assertion = laptop.sign(header, payload);
        REQUIRE(authority.loginWithKey(laptop.publicKey(), assertion)
                    .has_value());
        REQUIRE(refused(laptop.publicKey(), assertion));
        // A fresh assertion from the same key is fine.
        payload["jti"] = IntegrationDatabase::randomJti();
        REQUIRE(authority.loginWithKey(laptop.publicKey(),
                                       laptop.sign(header, payload))
                    .has_value());
    }
    SECTION("The subject is matched case-insensitively")
    {
        payload["sub"] = toUpper(user);
        const auto token
            = authority.loginWithKey(laptop.publicKey(),
                                     laptop.sign(header, payload));
        REQUIRE(token.has_value());
        const auto [result, claims] = verifier.verify(*token);
        REQUIRE(claims.has_value());
        if (claims){REQUIRE(claims->getUser() == user);}
    }
    SECTION("An array audience naming this server is accepted")
    {
        payload["aud"] = boost::json::array {"someone-else", issuer};
        REQUIRE(authority.loginWithKey(laptop.publicKey(),
                                       laptop.sign(header, payload))
                    .has_value());
    }
    SECTION("Only the holder of a registered, active key gets in")
    {
        // Signed by a different key than the one presented.
        REQUIRE(refused(laptop.publicKey(), stranger.sign(header, payload)));
        // Signed by, and presenting, a key nobody registered.
        REQUIRE(refused(stranger.publicKey(), stranger.sign(header, payload)));
        // A revoked key.
        REQUIRE(refused(old.publicKey(), old.sign(header, payload)));
        REQUIRE_FALSE(seeder.hasLoggedIn(user));
    }
    SECTION("A key logs in only as its owner")
    {
        // user's key claiming to be other, and other's key claiming to be
        // user: the key decides who this is, and the claim disagrees.
        payload["sub"] = other;
        const auto assertion = laptop.sign(header, payload);
        REQUIRE(refused(laptop.publicKey(), assertion));
        payload["sub"] = user;
        REQUIRE(refused(othersKey.publicKey(),
                        othersKey.sign(header, payload)));
        // The refusal didn't burn the jti: checked before consuming.
        REQUIRE(authority.loginWithKey(laptop.publicKey(),
                                       laptop.sign(header, payload))
                    .has_value());
    }
    SECTION("A tampered assertion is refused")
    {
        // Swap in another payload under the original signature.
        const auto assertion = laptop.sign(header, payload);
        auto forged = payload;
        forged["sub"] = other;
        const auto firstDot = assertion.find('.');
        const auto lastDot = assertion.rfind('.');
        const auto tampered
            = assertion.substr(0, firstDot) + "."
            + IntegrationDatabase::toBase64Url(boost::json::serialize(forged))
            + assertion.substr(lastDot);
        REQUIRE(refused(laptop.publicKey(), tampered));
        // A flipped signature character.
        auto flipped = assertion;
        flipped.back() = flipped.back() == 'A' ? 'B' : 'A';
        REQUIRE(refused(laptop.publicKey(), flipped));
    }
    SECTION("The assertion must be short-lived and current")
    {
        auto expired = payload;
        expired["iat"] = now - 30;
        expired["exp"] = now - 1;
        REQUIRE(refused(laptop.publicKey(), laptop.sign(header, expired)));

        auto tooLong = payload;
        tooLong["exp"] = now + 61;
        REQUIRE(refused(laptop.publicKey(), laptop.sign(header, tooLong)));

        auto future = payload;
        future["iat"] = now + 60;
        future["exp"] = now + 90;
        REQUIRE(refused(laptop.publicKey(), laptop.sign(header, future)));

        // Exactly the limit is fine.
        auto limit = payload;
        limit["exp"] = now + 60;
        REQUIRE(authority.loginWithKey(laptop.publicKey(),
                                       laptop.sign(header, limit))
                    .has_value());
    }
    SECTION("The assertion must be for this server")
    {
        payload["aud"] = "some-other-service";
        REQUIRE(refused(laptop.publicKey(), laptop.sign(header, payload)));
    }
    SECTION("Every claim is required")
    {
        for (const auto *claim : {"sub", "aud", "iat", "exp", "jti"})
        {
            INFO("without " << claim);
            auto missing = payload;
            missing.erase(claim);
            REQUIRE(refused(laptop.publicKey(), laptop.sign(header, missing)));
        }
        auto emptyJti = payload;
        emptyJti["jti"] = "";
        REQUIRE(refused(laptop.publicKey(), laptop.sign(header, emptyJti)));
        auto longJti = payload;
        longJti["jti"] = std::string(129, 'j');
        REQUIRE(refused(laptop.publicKey(), laptop.sign(header, longJti)));
        auto emptySubject = payload;
        emptySubject["sub"] = "";
        REQUIRE(refused(laptop.publicKey(),
                        laptop.sign(header, emptySubject)));
    }
    SECTION("The header cannot choose the algorithm")
    {
        // Correctly signed with Ed25519, but claiming otherwise.
        for (const auto *algorithm : {"none", "HS256", "RS256", "eddsa"})
        {
            INFO("alg = " << algorithm);
            auto lying = header;
            lying["alg"] = algorithm;
            REQUIRE(refused(laptop.publicKey(), laptop.sign(lying, payload)));
        }
        auto noAlgorithm = header;
        noAlgorithm.erase("alg");
        REQUIRE(refused(laptop.publicKey(), laptop.sign(noAlgorithm, payload)));
    }
    SECTION("Malformed input is refused, not a server error")
    {
        const auto assertion = laptop.sign(header, payload);
        for (const std::string &garbage :
                 {std::string {}, std::string {"."}, std::string {".."},
                  std::string {"abc"}, std::string {"a.b"},
                  std::string {"a.b.c"}, assertion + ".extra",
                  "." + assertion, assertion.substr(0, assertion.rfind('.')),
                  assertion.substr(0, assertion.rfind('.') + 1),
                  assertion + "=",
                  std::string(4097, 'a')})
        {
            INFO("assertion = " << garbage.substr(0, 64));
            REQUIRE(refused(laptop.publicKey(), garbage));
        }
        // An oversized but otherwise valid assertion.
        auto padded = payload;
        padded["padding"] = std::string(4096, 'p');
        REQUIRE(refused(laptop.publicKey(), laptop.sign(header, padded)));
        // Public keys of the wrong length.
        auto shortKey = laptop.publicKey();
        shortKey.pop_back();
        REQUIRE(refused(shortKey, assertion));
        auto longKey = laptop.publicKey();
        longKey.push_back(0);
        REQUIRE(refused(longKey, assertion));
        REQUIRE(refused({}, assertion));
        // None of that burned the jti.
        REQUIRE(authority.loginWithKey(laptop.publicKey(), assertion)
                    .has_value());
    }
}
