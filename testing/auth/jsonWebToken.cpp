#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/jsonWebToken.hpp"
#include "uEventAnalysisToolBackend/auth/jsonWebTokenOptions.hpp"
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

/// @brief Options for an ed25519-signing authority.
JSONWebTokenOptions makeSignedOptions()
{
    JSONWebTokenOptions options;   // Algorithm defaults to EdDSA25519.
    options.setKeyPair({loadKey("ed25519-public-key.pem"),
                        loadKey("ed25519-private-key.pem")});
    return options;
}

/// @brief Options for an unsigned authority.
JSONWebTokenOptions makeUnsignedOptions()
{
    JSONWebTokenOptions options;
    options.setAlgorithm(JSONWebTokenOptions::Algorithm::Unsigned);
    return options;
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

TEST_CASE("UEventAnalysisToolBackend::Auth::JSONWebTokenOptions",
          "JSONWebTokenOptions")
{
    SECTION("Defaults")
    {
        const JSONWebTokenOptions options;
        REQUIRE(options.getAlgorithm()
                == JSONWebTokenOptions::Algorithm::EdDSA25519);
        REQUIRE(options.getTimeToLive() == std::chrono::minutes {15});
        REQUIRE_FALSE(options.hasKeyPair());
        REQUIRE_THROWS_AS(options.getKeyPair(), std::runtime_error);
    }
    SECTION("Time-to-live must be positive")
    {
        JSONWebTokenOptions options;
        REQUIRE_THROWS_AS(options.setTimeToLive(std::chrono::seconds {0}),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(options.setTimeToLive(std::chrono::seconds {-1}),
                          std::invalid_argument);
        options.setTimeToLive(std::chrono::hours {1});
        REQUIRE(options.getTimeToLive() == std::chrono::hours {1});
    }
    SECTION("Algorithm round trips")
    {
        JSONWebTokenOptions options;
        options.setAlgorithm(JSONWebTokenOptions::Algorithm::Unsigned);
        REQUIRE(options.getAlgorithm()
                == JSONWebTokenOptions::Algorithm::Unsigned);
    }
    SECTION("Empty keys throw; a valid pair round trips")
    {
        const auto publicKey = loadKey("ed25519-public-key.pem");
        const auto privateKey = loadKey("ed25519-private-key.pem");
        JSONWebTokenOptions options;
        REQUIRE_THROWS_AS(options.setKeyPair({"", privateKey}),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(options.setKeyPair({publicKey, ""}),
                          std::invalid_argument);
        REQUIRE_FALSE(options.hasKeyPair());

        options.setKeyPair({publicKey, privateKey});
        REQUIRE(options.hasKeyPair());
        REQUIRE(options.getKeyPair().first == publicKey);
        REQUIRE(options.getKeyPair().second == privateKey);
    }
}

TEST_CASE("UEventAnalysisToolBackend::Auth::JSONWebToken", "JSONWebToken")
{
    SECTION("Unsigned round trip")
    {
        JSONWebToken authenticator{makeUnsignedOptions(), nullptr};
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
        JSONWebToken authenticator{makeSignedOptions(), nullptr};
        REQUIRE(authenticator.isSigned());

        const auto token = authenticator.createToken("sam-i-am");
        REQUIRE_FALSE(token.empty());
        REQUIRE(std::count(token.begin(), token.end(), '.') == 2);

        REQUIRE(authenticator.authenticateBearer(token)
                == IAuthenticator::Result::Authenticated);
    }
    SECTION("A signing algorithm requires a key pair")
    {
        // Default options select EdDSA25519 but carry no key pair.
        const JSONWebTokenOptions options;
        REQUIRE_THROWS_AS((JSONWebToken{options, nullptr}),
                          std::invalid_argument);
    }
    SECTION("Permissions ride in the signed token")
    {
        const JSONWebToken authenticator{makeSignedOptions(), nullptr};

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
        const JSONWebToken authenticator{makeSignedOptions(), nullptr};

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
        JSONWebToken authenticator{makeSignedOptions(), nullptr};

        const auto token = authenticator.createToken("sam-i-am");
        const auto tamperedToken = tamperWithPayload(token);
        REQUIRE(tamperedToken != token);
        REQUIRE(authenticator.authenticateBearer(tamperedToken)
                == IAuthenticator::Result::InvalidCredentials);
    }
    SECTION("Algorithm mismatch is rejected")
    {
        JSONWebToken signedAuthenticator{makeSignedOptions(), nullptr};
        JSONWebToken unsignedAuthenticator{makeUnsignedOptions(), nullptr};

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
        JSONWebToken authenticator{makeUnsignedOptions(), nullptr};
        REQUIRE(authenticator.authenticateBearer("clearly-not-a-jwt")
                == IAuthenticator::Result::InvalidCredentials);
        REQUIRE(authenticator.authenticateBearer("still.not.ajwt")
                == IAuthenticator::Result::InvalidCredentials);
        REQUIRE_THROWS_AS(authenticator.authenticateBearer(""),
                          std::invalid_argument);
    }
    SECTION("Empty user throws")
    {
        const JSONWebToken authenticator{makeUnsignedOptions(), nullptr};
        REQUIRE_THROWS_AS(authenticator.createToken(""),
                          std::invalid_argument);
    }
    SECTION("Basic authentication is not implemented")
    {
        JSONWebToken authenticator{makeUnsignedOptions(), nullptr};
        REQUIRE(authenticator.authenticateBasic({"user", "password"})
                == IAuthenticator::Result::ServerError);
    }
}