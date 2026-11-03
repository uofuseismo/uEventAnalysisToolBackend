#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <boost/json/object.hpp>
#include <boost/json/value.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/null_sink.h>
#include "uEventAnalysisToolBackend/auth/administratorTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"

using namespace UEventAnalysisToolBackend::Auth;

// The tokens here are minted with jwt-cpp directly rather than by a login
// authority, so every claim can be set (or left out, or forged) by hand.
// User tokens are signed with the ed25519-*-key.pem pair and administrator
// tokens with the ed25519-admin-*-key.pem pair, as in deployment.

namespace
{

using Permissions = std::vector<std::pair<std::string, std::string>>;
using Result = IAuthenticator::Result;

const std::string issuer{"ueat-test"};
const std::string userScope{"user"};
const std::string administratorScope{"admin"};

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

struct KeyPair
{
    std::string publicKey;
    std::string privateKey;
};

[[nodiscard]] const KeyPair &userKeys()
{
    static const KeyPair keys{loadKey("ed25519-public-key.pem"),
                              loadKey("ed25519-private-key.pem")};
    return keys;
}

[[nodiscard]] const KeyPair &administratorKeys()
{
    static const KeyPair keys{loadKey("ed25519-admin-public-key.pem"),
                              loadKey("ed25519-admin-private-key.pem")};
    return keys;
}

/// @brief What goes into a token.  An unset optional leaves the claim out.
struct TokenContents
{
    std::optional<std::string> subject{"sam-i-am"};
    std::optional<std::string> issuer{::issuer};
    std::optional<std::string> scope{userScope};
    /// Relative to now; negative is already expired.
    std::optional<std::chrono::seconds> expiresIn{std::chrono::minutes {5}};
    std::optional<Permissions> permissions;
};

enum class Signer : std::uint8_t
{
    User,
    Administrator,
    Unsigned
};

[[nodiscard]] std::string mint(const TokenContents &contents,
                               const Signer signer)
{
    using Claim = jwt::basic_claim<jwt::traits::boost_json>;
    const auto now = std::chrono::system_clock::now();
    auto token = jwt::create<jwt::traits::boost_json> ();
    token.set_type("JWT").set_issued_at(now);
    if (contents.subject){token.set_subject(*contents.subject);}
    if (contents.issuer){token.set_issuer(*contents.issuer);}
    if (contents.scope)
    {
        token.set_payload_claim("scope", Claim {*contents.scope});
    }
    if (contents.expiresIn)
    {
        token.set_expires_at(now + *contents.expiresIn);
    }
    if (contents.permissions)
    {
        boost::json::object object;
        for (const auto &[schema, permission] : *contents.permissions)
        {
            object[schema] = permission;
        }
        token.set_payload_claim("permissions",
                                Claim {boost::json::value {object}});
    }
    switch (signer)
    {
        case Signer::User:
            return token.sign(jwt::algorithm::ed25519(
                userKeys().publicKey, userKeys().privateKey, "", ""));
        case Signer::Administrator:
            return token.sign(jwt::algorithm::ed25519(
                administratorKeys().publicKey,
                administratorKeys().privateKey, "", ""));
        case Signer::Unsigned:
            return token.sign(jwt::algorithm::none {});
    }
    throw std::logic_error("Unhandled signer");
}

[[nodiscard]] TokenVerifierOptions makeOptions(const std::string &publicKey)
{
    TokenVerifierOptions options;
    options.setPublicKeyAndAlgorithm(
        publicKey, TokenVerifierOptions::Algorithm::EdDSA25519);
    options.setIssuer(issuer);
    return options;
}

[[nodiscard]] TokenVerifierOptions userOptions()
{
    return makeOptions(userKeys().publicKey);
}

[[nodiscard]] TokenVerifierOptions administratorOptions()
{
    return makeOptions(administratorKeys().publicKey);
}

/// @brief Keeps the expected rejection warnings out of the test output.
[[nodiscard]] std::shared_ptr<spdlog::logger> quietLogger()
{
    return std::make_shared<spdlog::logger>(
        "tokenVerifierTests", std::make_shared<spdlog::sinks::null_sink_mt> ());
}

[[nodiscard]] Permissions sorted(Permissions permissions)
{
    std::ranges::sort(permissions);
    return permissions;
}

[[nodiscard]] Permissions permissionsOf(const Claims &claims)
{
    return sorted(Permissions(claims.begin(), claims.end()));
}

/// @brief The header.payload.signature pieces of a compact JWT.
[[nodiscard]] std::vector<std::string> split(const std::string &token)
{
    std::vector<std::string> parts;
    std::string part;
    std::istringstream stream{token};
    while (std::getline(stream, part, '.')){parts.push_back(part);}
    return parts;
}

/// @brief The claims of an accepted token.
[[nodiscard]] const Claims &requireClaims(const std::optional<Claims> &claims)
{
    REQUIRE(claims.has_value());
    if (!claims){throw std::logic_error("Unreachable");}
    return *claims;
}

template<typename T>
void requireRejected(const T &result, const Result expected)
{
    REQUIRE(result.first == expected);
    REQUIRE_FALSE(result.second.has_value());
}

/// @brief Every way a token can be bad that does not depend on which
///        verifier sees it.  The signer and scope are the ones the
///        verifier would otherwise accept.
template<typename Verifier>
void requireCommonRejections(const Verifier &verifier,
                             const Signer signer,
                             const std::string &scope)
{
    TokenContents good;
    good.scope = scope;

    SECTION("Garbage is rejected")
    {
        for (const std::string token : {"", "not-a-jwt", "a.b.c", "..."})
        {
            INFO(token);
            requireRejected(verifier.verify(token), Result::InvalidCredentials);
        }
    }
    SECTION("Wrong issuer is rejected")
    {
        auto contents = good;
        contents.issuer = "someone-else";
        requireRejected(verifier.verify(mint(contents, signer)),
                        Result::InvalidCredentials);
    }
    SECTION("Missing issuer is rejected")
    {
        auto contents = good;
        contents.issuer.reset();
        requireRejected(verifier.verify(mint(contents, signer)),
                        Result::InvalidCredentials);
    }
    SECTION("Expired token is rejected")
    {
        auto contents = good;
        contents.expiresIn = std::chrono::seconds {-60};
        requireRejected(verifier.verify(mint(contents, signer)),
                        Result::InvalidCredentials);
    }
    SECTION("Unsigned token is rejected")
    {
        // The classic algorithm-confusion attack: alg=none with forged
        // claims.
        requireRejected(verifier.verify(mint(good, Signer::Unsigned)),
                        Result::InvalidCredentials);
    }
    SECTION("Token with its signature stripped is rejected")
    {
        const auto parts = split(mint(good, signer));
        REQUIRE(parts.size() == 3);
        requireRejected(verifier.verify(parts[0] + "." + parts[1] + "."),
                        Result::InvalidCredentials);
    }
    SECTION("Tampered payload is rejected")
    {
        auto lesser = good;
        lesser.subject = "sam-i-am";
        auto greater = good;
        greater.subject = "guy-am-i";
        const auto original = split(mint(lesser, signer));
        const auto forged = split(mint(greater, signer));
        REQUIRE(original.size() == 3);
        REQUIRE(forged.size() == 3);
        // Someone else's claims under sam-i-am's signature.
        requireRejected(verifier.verify(original[0] + "." + forged[1]
                                      + "." + original[2]),
                        Result::InvalidCredentials);
    }
    SECTION("Token without an expiry is never accepted")
    {
        auto contents = good;
        contents.expiresIn.reset();
        REQUIRE(verifier.verify(mint(contents, signer)).first
                != Result::Authenticated);
    }
    SECTION("Token without a subject is never accepted")
    {
        auto contents = good;
        contents.subject.reset();
        REQUIRE(verifier.verify(mint(contents, signer)).first
                != Result::Authenticated);
    }
    SECTION("Token without a scope is never accepted")
    {
        auto contents = good;
        contents.scope.reset();
        REQUIRE(verifier.verify(mint(contents, signer)).first
                != Result::Authenticated);
    }
}

}

TEST_CASE("UEventAnalysisToolBackend::Auth::UserTokenVerifier",
          "[TokenVerifiers]")
{
    SECTION("An issuer is required")
    {
        TokenVerifierOptions options;
        options.setPublicKeyAndAlgorithm(
            userKeys().publicKey, TokenVerifierOptions::Algorithm::EdDSA25519);
        REQUIRE_THROWS(UserTokenVerifier {options, quietLogger()});
    }
    SECTION("A null logger is allowed")
    {
        const UserTokenVerifier verifier{userOptions(), nullptr};
        REQUIRE(verifier.isInitialized());
    }

    const UserTokenVerifier verifier{userOptions(), quietLogger()};
    REQUIRE(verifier.isInitialized());

    SECTION("A user token is accepted and its claims unpacked")
    {
        TokenContents contents;
        contents.permissions = Permissions{{"utah", "read_write"},
                                           {"sandbox_utah", "read_write"},
                                           {"ynp", "read_only"}};
        const auto before
            = std::chrono::floor<std::chrono::seconds>(
                  std::chrono::system_clock::now());
        const auto [result, maybeClaims]
            = verifier.verify(mint(contents, Signer::User));
        REQUIRE(result == Result::Authenticated);
        const Claims &claims = requireClaims(maybeClaims);
        REQUIRE(claims.getUser() == "sam-i-am");
        REQUIRE(claims.getScope() == Claims::Scope::User);
        REQUIRE_FALSE(Claims::isAdministrator(claims));
        REQUIRE(permissionsOf(claims) == sorted(contents.permissions.value()));
        // JWT times are whole seconds.
        const auto expiresAt = claims.getExpirationTime();
        REQUIRE(expiresAt >= before + std::chrono::minutes {5});
        REQUIRE(expiresAt <= before + std::chrono::minutes {5}
                                    + std::chrono::seconds {2});
    }
    SECTION("A user token without permissions has none")
    {
        const auto [result, maybeClaims]
            = verifier.verify(mint(TokenContents {}, Signer::User));
        REQUIRE(result == Result::Authenticated);
        const Claims &claims = requireClaims(maybeClaims);
        REQUIRE(claims.begin() == claims.end());
    }
    SECTION("A token signed with the administrator key is rejected")
    {
        // Even with a user scope: the user verifier does not hold the
        // administrator public key.
        requireRejected(verifier.verify(mint(TokenContents {},
                                             Signer::Administrator)),
                        Result::InvalidCredentials);
    }
    SECTION("A user-signed token claiming the administrator scope is rejected")
    {
        TokenContents contents;
        contents.scope = administratorScope;
        REQUIRE(verifier.verify(mint(contents, Signer::User)).first
                != Result::Authenticated);
    }
    SECTION("Clock leeway admits a token that only just expired")
    {
        auto options = userOptions();
        options.setClockLeeway(std::chrono::seconds {30});
        const UserTokenVerifier lenient{options, quietLogger()};
        TokenContents contents;
        contents.expiresIn = std::chrono::seconds {-10};
        REQUIRE(lenient.verify(mint(contents, Signer::User)).first
                == Result::Authenticated);
        contents.expiresIn = std::chrono::seconds {-60};
        REQUIRE(lenient.verify(mint(contents, Signer::User)).first
                == Result::InvalidCredentials);
    }
    SECTION("Copies and moves still verify")
    {
        const auto token = mint(TokenContents {}, Signer::User);
        const UserTokenVerifier copied{verifier}; // NOLINT(performance-unnecessary-copy-initialization)
        REQUIRE(copied.verify(token).first == Result::Authenticated);
        UserTokenVerifier assigned{userOptions(), quietLogger()};
        assigned = verifier;
        REQUIRE(assigned.verify(token).first == Result::Authenticated);
        UserTokenVerifier source{verifier};
        const UserTokenVerifier moved{std::move(source)};
        REQUIRE(moved.verify(token).first == Result::Authenticated);
    }

    requireCommonRejections(verifier, Signer::User, userScope);
}

TEST_CASE("UEventAnalysisToolBackend::Auth::AdministratorTokenVerifier",
          "[TokenVerifiers]")
{
    SECTION("An issuer is required")
    {
        TokenVerifierOptions options;
        options.setPublicKeyAndAlgorithm(
            administratorKeys().publicKey,
            TokenVerifierOptions::Algorithm::EdDSA25519);
        REQUIRE_THROWS(AdministratorTokenVerifier {options, quietLogger()});
    }

    const AdministratorTokenVerifier verifier{administratorOptions(),
                                              quietLogger()};
    REQUIRE(verifier.isInitialized());

    SECTION("An administrator token is accepted")
    {
        TokenContents contents;
        contents.scope = administratorScope;
        const auto [result, maybeClaims]
            = verifier.verify(mint(contents, Signer::Administrator));
        REQUIRE(result == Result::Authenticated);
        const Claims &claims = requireClaims(maybeClaims);
        REQUIRE(claims.getUser() == "sam-i-am");
        REQUIRE(claims.getScope() == Claims::Scope::Administrator);
        REQUIRE(Claims::isAdministrator(claims));
        REQUIRE(claims.begin() == claims.end());
    }
    SECTION("A token signed with the user key is rejected")
    {
        // Even with the administrator scope: a stolen or forged user
        // token can never reach the admin service.
        TokenContents contents;
        contents.scope = administratorScope;
        requireRejected(verifier.verify(mint(contents, Signer::User)),
                        Result::InvalidCredentials);
    }
    SECTION("An administrator-signed token with the user scope is rejected")
    {
        REQUIRE(verifier.verify(mint(TokenContents {},
                                     Signer::Administrator)).first
                != Result::Authenticated);
    }
    SECTION("An administrator token carrying schema permissions is rejected")
    {
        // A correctly signed one means the minter is broken - our fault,
        // not the client's.
        TokenContents contents;
        contents.scope = administratorScope;
        contents.permissions = Permissions{{"utah", "read_write"}};
        requireRejected(verifier.verify(mint(contents, Signer::Administrator)),
                        Result::ServerError);
    }

    requireCommonRejections(verifier, Signer::Administrator,
                            administratorScope);
}

TEST_CASE("UEventAnalysisToolBackend::Auth token verifiers require a public key",
          "[TokenVerifiers]")
{
    // Without a key a verifier would have to accept unsigned tokens, and
    // anyone could then forge any claims.
    TokenVerifierOptions options;
    options.setIssuer(issuer);
    REQUIRE_THROWS(UserTokenVerifier {options, quietLogger()});
    REQUIRE_THROWS(AdministratorTokenVerifier {options, quietLogger()});
}
