#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/authNZ.hpp"
#include "uEventAnalysisToolBackend/auth/jsonWebToken.hpp"

using namespace UEventAnalysisToolBackend::Auth;

TEST_CASE("UEventAnalysisToolBackend::Auth::AuthNZ", "AuthNZ")
{
    SECTION("Authorization respects the permission hierarchy")
    {
        JSONWebToken::Claims identity;
        identity.user = "sam-i-am";
        identity.permissions
            = std::vector<std::pair<std::string, std::string>>
              {
                  {"utah", "read_write"},
                  {"ynp",  "read_only"}
              };

        // Exact grants hold.
        REQUIRE(AuthNZ::isAuthorized(identity, "utah", "read_write"));
        REQUIRE(AuthNZ::isAuthorized(identity, "ynp", "read_only"));
        // Writers can read.
        REQUIRE(AuthNZ::isAuthorized(identity, "utah", "read_only"));
        // Readers cannot write.
        REQUIRE_FALSE(AuthNZ::isAuthorized(identity, "ynp", "read_write"));
        // No grant on the schema at all.
        REQUIRE_FALSE(AuthNZ::isAuthorized(identity, "forge", "read_only"));
        REQUIRE_FALSE(AuthNZ::isAuthorized(identity, "forge", "read_write"));
    }
    SECTION("No permissions authorizes nothing")
    {
        JSONWebToken::Claims identity;
        identity.user = "sam-i-am";
        REQUIRE_FALSE(AuthNZ::isAuthorized(identity, "utah", "read_only"));
        REQUIRE_FALSE(AuthNZ::isAuthorized(identity, "utah", "read_write"));
    }
}