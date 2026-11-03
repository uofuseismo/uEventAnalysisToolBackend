#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth;

TEST_CASE("UEventAnalysisToolBackend::Auth::TokenVerifierOptions",
          "[TokenVerifierOptions]")
{
    // The options only carry the key; it is not parsed until a verifier
    // is built, so any non-empty text will do here.
    const std::string publicKey{"-----BEGIN PUBLIC KEY-----"};
    const std::string issuer{"ueat-test"};
    constexpr auto algorithm{TokenVerifierOptions::Algorithm::EdDSA25519};

    SECTION("Defaults")
    {
        const TokenVerifierOptions options;
        REQUIRE_FALSE(options.hasPublicKeyAndAlgorithm());
        REQUIRE_FALSE(options.hasIssuer());
        REQUIRE(options.getClockLeeway() == std::chrono::seconds {0});
        REQUIRE_THROWS(options.getPublicKey());
        REQUIRE_THROWS(options.getAlgorithm());
        REQUIRE_THROWS(options.getIssuer());
    }
    SECTION("Public key and algorithm")
    {
        TokenVerifierOptions options;
        options.setPublicKeyAndAlgorithm(publicKey, algorithm);
        REQUIRE(options.hasPublicKeyAndAlgorithm());
        REQUIRE(options.getPublicKey() == publicKey);
        REQUIRE(options.getAlgorithm() == algorithm);
    }
    SECTION("Empty public key throws and leaves the options unset")
    {
        TokenVerifierOptions options;
        REQUIRE_THROWS_AS(options.setPublicKeyAndAlgorithm("", algorithm),
                          std::invalid_argument);
        REQUIRE_FALSE(options.hasPublicKeyAndAlgorithm());
    }
    SECTION("Issuer")
    {
        TokenVerifierOptions options;
        options.setIssuer(issuer);
        REQUIRE(options.hasIssuer());
        REQUIRE(options.getIssuer() == issuer);
        REQUIRE_THROWS_AS(options.setIssuer(""), std::invalid_argument);
        REQUIRE(options.getIssuer() == issuer);
    }
    SECTION("Clock leeway")
    {
        TokenVerifierOptions options;
        options.setClockLeeway(std::chrono::seconds {30});
        REQUIRE(options.getClockLeeway() == std::chrono::seconds {30});
        options.setClockLeeway(std::chrono::seconds {0});
        REQUIRE(options.getClockLeeway() == std::chrono::seconds {0});
        REQUIRE_THROWS_AS(options.setClockLeeway(std::chrono::seconds {-1}),
                          std::invalid_argument);
        REQUIRE(options.getClockLeeway() == std::chrono::seconds {0});
    }
    SECTION("Copy and move")
    {
        TokenVerifierOptions options;
        options.setPublicKeyAndAlgorithm(publicKey, algorithm);
        options.setIssuer(issuer);
        options.setClockLeeway(std::chrono::seconds {5});

        const auto requireSame = [&](const TokenVerifierOptions &copy)
        {
            REQUIRE(copy.getPublicKey() == publicKey);
            REQUIRE(copy.getAlgorithm() == algorithm);
            REQUIRE(copy.getIssuer() == issuer);
            REQUIRE(copy.getClockLeeway() == std::chrono::seconds {5});
        };

        const TokenVerifierOptions copied{options};
        requireSame(copied);

        TokenVerifierOptions assigned;
        assigned = options;
        requireSame(assigned);

        // The copies are independent.
        options.setIssuer("someone-else");
        REQUIRE(copied.getIssuer() == issuer);

        TokenVerifierOptions moved{std::move(assigned)};
        requireSame(moved);

        TokenVerifierOptions moveAssigned;
        moveAssigned = std::move(moved);
        requireSame(moveAssigned);
    }
}
