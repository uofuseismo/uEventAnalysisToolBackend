#include <array>
#include <cctype>
#include <chrono>
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
#include "uEventAnalysisToolBackend/auth/userList.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "integrationDatabase.hpp"
#include "keyAssertion.hpp"
#include "userSeeder.hpp"

using namespace UEventAnalysisToolBackend::Auth;

// Integration test: a user listing their own login keys.  Same plumbing
// as userKeys.cpp.

namespace
{

const std::string issuer{"ueat-user-keys-list-test"};
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
    return result;
}

/// @result The fingerprint a client computes from the raw key, done here
///         with libsodium so it does not agree with the database by
///         construction.
[[nodiscard]] std::string fingerprint(const IntegrationDatabase::KeyPair &key)
{
    const auto publicKey = key.publicKey();
    std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), publicKey.data(), publicKey.size());
    return "SHA256:"
         + IntegrationDatabase::toBase64(
               digest.data(), digest.size(),
               sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
}

[[nodiscard]] std::string toUpper(std::string s)
{
    for (auto &c : s){c = static_cast<char> (std::toupper(c));}
    return s;
}

template<typename Key>
[[nodiscard]] std::vector<std::string> namesOf(const std::vector<Key> &keys)
{
    std::vector<std::string> result;
    result.reserve(keys.size());
    for (const auto &key : keys){result.push_back(key.getName());}
    return result;
}

}

TEST_CASE("UEventAnalysisToolBackend::Auth::UserLoginAuthority::listKeys",
          "[.integration][UserLoginAuthority]")
{
    using Names = std::vector<std::string>;
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-user-keys-list-test-" + suffix;
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
    const std::string keyless{"i-am-sam-" + suffix};
    INFO("suffix = " << suffix);

    // Four states for user, registered in this order:
    //   laptop  active, never expires
    //   live    active, expires in an hour
    //   dated   expired, never revoked
    //   old     revoked
    const IntegrationDatabase::KeyPair laptop;
    const IntegrationDatabase::KeyPair live;
    const IntegrationDatabase::KeyPair dated;
    const IntegrationDatabase::KeyPair old;
    const IntegrationDatabase::KeyPair theirs;

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(user, false);
    seeder.addKey(user, "laptop", laptop.encodedPublicKey());
    seeder.addKey(user, "live", live.encodedPublicKey(), 3600);
    seeder.addKey(user, "dated", dated.encodedPublicKey(), 1);
    seeder.addKey(user, "old", old.encodedPublicKey());
    seeder.revokeKey(user, "old");
    seeder.addUser(other, false);
    seeder.addKey(other, "theirs", theirs.encodedPublicKey());
    seeder.addUser(keyless, false);
    // Let dated lapse.
    std::this_thread::sleep_for(std::chrono::milliseconds {1100});

    const UserLoginAuthority authority{
        options(*backendCredentials),
        IntegrationDatabase::quietLogger("userKeysListTests")};
    REQUIRE(authority.isInitialized());

    SECTION("Keys are split by state, in the order they were registered")
    {
        const auto keys = authority.listKeys(user);
        REQUIRE(keys.has_value());
        const auto &[active, inactive] = keys.value();
        REQUIRE(namesOf(active) == Names {"laptop", "live"});
        REQUIRE(namesOf(inactive) == Names {"dated", "old"});

        REQUIRE(active.at(0).getFingerprint() == fingerprint(laptop));
        REQUIRE(active.at(1).getFingerprint() == fingerprint(live));
        REQUIRE(inactive.at(0).getFingerprint() == fingerprint(dated));
        REQUIRE(inactive.at(1).getFingerprint() == fingerprint(old));

        // Expiry: unset means never.
        REQUIRE_FALSE(active.at(0).getExpiration().has_value());
        REQUIRE(active.at(1).getExpiration().has_value());
        REQUIRE(active.at(1).getExpiration().value_or(std::chrono::microseconds {0})
              > active.at(1).getWhenRegistered());

        // Why each stopped, and when.
        REQUIRE(inactive.at(0).getReason() == InactiveKey::Reason::Expired);
        REQUIRE(inactive.at(1).getReason() == InactiveKey::Reason::Revoked);
        for (const auto &key : inactive)
        {
            REQUIRE(key.getWhenInvalidated() > key.getWhenRegistered());
        }
        // Registered in order, a moment apart.
        REQUIRE(active.at(0).getWhenRegistered()
              < active.at(1).getWhenRegistered());
        REQUIRE(active.at(1).getWhenRegistered()
              < inactive.at(0).getWhenRegistered());
    }
    SECTION("Last use shows up once a key logs in")
    {
        const auto before = authority.listKeys(user);
        REQUIRE(before.has_value());
        REQUIRE_FALSE(before.value().first.at(0).getLastUsed().has_value());

        REQUIRE(authority.loginWithKey(
                    laptop.publicKey(),
                    laptop.sign(IntegrationDatabase::assertionHeader(),
                                IntegrationDatabase::assertionPayload(
                                    user, issuer))).has_value());

        const auto after = authority.listKeys(user);
        REQUIRE(after.has_value());
        const auto &active = after.value().first;
        REQUIRE(active.at(0).getLastUsed().has_value());
        REQUIRE_FALSE(active.at(1).getLastUsed().has_value());
    }
    SECTION("A user sees only their own keys, by any spelling of their name")
    {
        const auto shouted = authority.listKeys(" " + toUpper(user) + " ");
        REQUIRE(shouted.has_value());
        REQUIRE(namesOf(shouted.value().first) == Names {"laptop", "live"});

        const auto theirsListed = authority.listKeys(other);
        REQUIRE(theirsListed.has_value());
        REQUIRE(namesOf(theirsListed.value().first) == Names {"theirs"});
        REQUIRE(theirsListed.value().second.empty());
    }
    SECTION("A user who does not exist is not authenticated")
    {
        // The name comes from a verified token, so this is a user deleted
        // since it was minted.
        for (const auto &name : {std::string {"nobody-" + suffix},
                                 std::string {}})
        {
            const auto keys = authority.listKeys(name);
            REQUIRE_FALSE(keys.has_value());
            REQUIRE(keys.error() == UserLoginAuthority::KeyError::Unauthenticated);
        }
    }
    SECTION("A user with no keys gets two empty lists")
    {
        const auto keys = authority.listKeys(keyless);
        REQUIRE(keys.has_value());
        REQUIRE(keys.value().first.empty());
        REQUIRE(keys.value().second.empty());
    }
}
