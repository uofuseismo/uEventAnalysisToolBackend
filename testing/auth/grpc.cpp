#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/grpc.hpp"

using namespace UEventAnalysisToolBackend::Auth;

TEST_CASE("UEventAnalysisToolBackend::Auth::GRPC", "DecodeBase64")
{
    SECTION("Standard use case")
    {
        // echo "user:monkey" | base64
        const std::string base64{"dXNlcjptb25rZXkK"};
        auto [user, password] = decodeBase64(base64);
        REQUIRE(user == "user");
        REQUIRE(password == "monkey");
    }
    SECTION("Password has a colon")
    {
        // echo "user2:monk:ey" | base64
        const std::string base64{"dXNlcjI6bW9uazpleQo="};
        auto [user, password] = decodeBase64(base64);
        REQUIRE(user == "user2");
        REQUIRE(password == "monk:ey");
    }
    SECTION("Password is empty")
    {
        // echo "user3:" | base64
        const std::string base64{"dXNlcjM6Cg=="};
        auto [user, password] = decodeBase64(base64);
        REQUIRE(user == "user3");
        REQUIRE(password == "");
    }
    SECTION("Fail empty creds")
    {
        REQUIRE_THROWS_AS(decodeBase64(""), std::invalid_argument);
    }
    SECTION("Fail malformed - no colon")
    {
        // echo "usermonkey" | base64
        REQUIRE_THROWS_AS(
           decodeBase64("dXNlcm1vbmtleQo="), std::invalid_argument);
    }
    SECTION("Fail empty user")
    {
        // echo ":monkey" | base64
        REQUIRE_THROWS_AS(decodeBase64("Om1vbmtleQo="), std::invalid_argument);
    }
}
 
