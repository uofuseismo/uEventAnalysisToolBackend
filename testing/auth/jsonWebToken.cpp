#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/jsonWebToken.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"

using namespace UEventAnalysisToolBackend::Auth;

namespace
{

/// @brief Loads a PEM key from the testing data directory.
std::string loadKey(const std::string &fileName)
{
    const std::filesystem::path path
        = std::filesystem::path{TESTING_DATA_DIR}/"keys"/fileName;
    if (!std::filesystem::exists(path))
    {
        throw std::runtime_error("Key file " + std::string{path}
                               + " does not exist");
    }
    const std::ifstream keyFile{path};
    std::stringstream stream;
    stream << keyFile.rdbuf();
    return stream.str();
}

/// @brief Corrupts the payload of a header.payload.signature token so the
///        signature no longer matches.
std::string tamperWithPayload(const std::string &token)
{
    auto firstDot = token.find('.');
    auto payloadStart = firstDot + 1;
    // Flip a base64url character in the payload.
    auto result = token;
    result.at(payloadStart) = result.at(payloadStart) == 'A' ? 'B' : 'A';
    return result;
}

}

TEST_CASE("UEventAnalysisToolBackend::Auth::JSONWebToken", "JSONWebToken")
{
    SECTION("Unsigned round trip")
    {
        JSONWebToken authenticator{nullptr};
        REQUIRE_FALSE(authenticator.isSigned());

        const auto token = authenticator.createToken("sam-i-am");
        REQUIRE_FALSE(token.empty());
        // A JWT is three base64url sections: header.payload.signature.
        REQUIRE(std::count(token.begin(), token.end(), '.') == 2);

        REQUIRE(authenticator.authenticateBearer(token)
                == IAuthenticator::Result::Authenticated);
    }
    SECTION("Signed round trip")
    {
        const auto publicKey = loadKey("ed25519-public-key.pem");
        const auto privateKey = loadKey("ed25519-private-key.pem");
        JSONWebToken authenticator{{publicKey, privateKey}, nullptr};
        REQUIRE(authenticator.isSigned());

        const auto token = authenticator.createToken("sam-i-am");
        REQUIRE_FALSE(token.empty());
        REQUIRE(std::count(token.begin(), token.end(), '.') == 2);

        REQUIRE(authenticator.authenticateBearer(token)
                == IAuthenticator::Result::Authenticated);
    }
    SECTION("Permissions ride in the signed token")
    {
        const auto publicKey = loadKey("ed25519-public-key.pem");
        const auto privateKey = loadKey("ed25519-private-key.pem");
        const JSONWebToken authenticator{{publicKey, privateKey}, nullptr};

        const std::vector<std::pair<std::string, std::string>> permissions
        {
            {"utah", "read_write"},
            {"ynp",  "read_only"}
        };
        const auto token = authenticator.createToken("sam-i-am", permissions);

        const auto [result, claims] = authenticator.verify(token);
        REQUIRE(result == IAuthenticator::Result::Authenticated);
        REQUIRE(claims.has_value());
        //NOLINTBEGIN(bugprone-unchecked-optional-access)
        REQUIRE(claims->user == "sam-i-am");
        REQUIRE(claims->permissions.size() == permissions.size());
        for (const auto &permission : permissions)
        {
            REQUIRE(std::find(claims->permissions.begin(),
                              claims->permissions.end(),
                              permission) != claims->permissions.end());
        }
        //NOLINTEND(bugprone-unchecked-optional-access)
    }
    SECTION("Token without permissions verifies with empty permissions")
    {
        const auto publicKey = loadKey("ed25519-public-key.pem");
        const auto privateKey = loadKey("ed25519-private-key.pem");
        const JSONWebToken authenticator{{publicKey, privateKey}, nullptr};

        const auto token = authenticator.createToken("sam-i-am");
        const auto [result, claims] = authenticator.verify(token);
        REQUIRE(result == IAuthenticator::Result::Authenticated);
        REQUIRE(claims.has_value());
        //NOLINTBEGIN(bugprone-unchecked-optional-access)
        REQUIRE(claims->user == "sam-i-am");
        REQUIRE(claims->permissions.empty());
        //NOLINTEND(bugprone-unchecked-optional-access)
    }
    SECTION("Tampered signed token is rejected")
    {
        const auto publicKey = loadKey("ed25519-public-key.pem");
        const auto privateKey = loadKey("ed25519-private-key.pem");
        JSONWebToken authenticator{{publicKey, privateKey}, nullptr};

        const auto token = authenticator.createToken("sam-i-am");
        const auto tamperedToken = tamperWithPayload(token);
        REQUIRE(tamperedToken != token);
        REQUIRE(authenticator.authenticateBearer(tamperedToken)
                == IAuthenticator::Result::InvalidCredentials);
    }
    SECTION("Algorithm mismatch is rejected")
    {
        const auto publicKey = loadKey("ed25519-public-key.pem");
        const auto privateKey = loadKey("ed25519-private-key.pem");
        JSONWebToken signedAuthenticator{{publicKey, privateKey}, nullptr};
        JSONWebToken unsignedAuthenticator{nullptr};

        // An unsigned (algorithm none) token must not pass the ed25519
        // verifier and vice versa.
        const auto unsignedToken = unsignedAuthenticator.createToken("sam-i-am");
        REQUIRE(signedAuthenticator.authenticateBearer(unsignedToken)
                == IAuthenticator::Result::InvalidCredentials);

        const auto signedToken = signedAuthenticator.createToken("sam-i-am");
        REQUIRE(unsignedAuthenticator.authenticateBearer(signedToken)
                == IAuthenticator::Result::InvalidCredentials);
    }
    SECTION("Garbage tokens are rejected")
    {
        JSONWebToken authenticator{nullptr};
        REQUIRE(authenticator.authenticateBearer("clearly-not-a-jwt")
                == IAuthenticator::Result::InvalidCredentials);
        REQUIRE(authenticator.authenticateBearer("still.not.ajwt")
                == IAuthenticator::Result::InvalidCredentials);
        REQUIRE_THROWS_AS(authenticator.authenticateBearer(""),
                          std::invalid_argument);
    }
    SECTION("Empty user throws")
    {
        const JSONWebToken authenticator{nullptr};
        REQUIRE_THROWS_AS(authenticator.createToken(""),
                          std::invalid_argument);
    }
    SECTION("Empty keys throw")
    {
        const auto publicKey = loadKey("ed25519-public-key.pem");
        const auto privateKey = loadKey("ed25519-private-key.pem");
        REQUIRE_THROWS_AS((JSONWebToken{{"", privateKey}, nullptr}),
                          std::invalid_argument);
        REQUIRE_THROWS_AS((JSONWebToken{{publicKey, ""}, nullptr}),
                          std::invalid_argument);
    }
    SECTION("Basic authentication is not implemented")
    {
        JSONWebToken authenticator{nullptr};
        REQUIRE(authenticator.authenticateBasic({"user", "password"})
                == IAuthenticator::Result::ServerError);
    }
}