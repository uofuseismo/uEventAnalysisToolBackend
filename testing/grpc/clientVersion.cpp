#include <optional>
#include <stdexcept>
#include <string>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/grpc/clientVersion.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

// The frontend sends its version in x-client-version and the login routes
// compare it to a configured minimum.  What matters is that every real
// version parses, that nothing else does - the value comes straight off
// the wire and lands in the logs - and that the ordering is numeric.

namespace
{

/// @result The version, which the test requires to have parsed.
[[nodiscard]] ClientVersion parsed(const std::string &version)
{
    INFO("version = '" << version << "'");
    const auto result = ClientVersion::parse(version);
    REQUIRE(result.has_value());
    return result.value_or(ClientVersion {"0.0.0"});
}

}

TEST_CASE("UEventAnalysisToolBackend::GRPC::ClientVersion", "[ClientVersion]")
{
    SECTION("MAJOR.MINOR.PATCH parses")
    {
        REQUIRE(parsed("1.2.3").toString() == "1.2.3");
        REQUIRE(parsed("0.0.0").toString() == "0.0.0");
        REQUIRE(parsed("10.20.300").toString() == "10.20.300");
    }
    SECTION("A pre-release or build suffix is accepted and dropped")
    {
        // Flutter's version: 1.2.3+45, as pubspec.yaml writes it.
        REQUIRE(parsed("1.2.3+45").toString() == "1.2.3");
        REQUIRE(parsed("1.2.3-beta").toString() == "1.2.3");
        REQUIRE(parsed("1.2.3-rc.1+build.7").toString() == "1.2.3");
    }
    SECTION("Leading zeros read as the number")
    {
        REQUIRE(parsed("01.002.0003") == parsed("1.2.3"));
    }
    SECTION("Anything else is refused")
    {
        const std::string tooLong{"1.2.3+" + std::string(59, 'x')};
        REQUIRE(tooLong.size() == 65);
        for (const auto &bad : {std::string {""},
                                std::string {" "},
                                // Not three parts.
                                std::string {"1"},
                                std::string {"1.2"},
                                std::string {"1.2.3.4"},
                                std::string {"1..3"},
                                std::string {".1.2.3"},
                                std::string {"1.2.3."},
                                // Not digits.
                                std::string {"v1.2.3"},
                                std::string {"1.x.3"},
                                std::string {"1.2.3a"},
                                std::string {"one.two.three"},
                                // Signs.  from_chars would take a leading
                                // minus; these fail because - or + starts
                                // the suffix, leaving too few numbers.
                                std::string {"-1.2.3"},
                                std::string {"+1.2.3"},
                                std::string {"1.-2.3"},
                                // Whitespace anywhere.
                                std::string {" 1.2.3"},
                                std::string {"1.2.3 "},
                                std::string {"1. 2.3"},
                                std::string {"1.2.3\n"},
                                // An empty or unprintable suffix.
                                std::string {"1.2.3-"},
                                std::string {"1.2.3+"},
                                std::string {"1.2.3-be ta"},
                                std::string {"1.2.3+\t45"},
                                std::string {"1.2.3-\xC3\xA9"},
                                // Too big for an int.
                                std::string {"99999999999.0.0"},
                                std::string {"1.99999999999.0"},
                                // Longer than any real version.
                                tooLong})
        {
            INFO("version = '" << bad << "'");
            REQUIRE_FALSE(ClientVersion::parse(bad).has_value());
            REQUIRE_THROWS_AS(ClientVersion {bad}, std::invalid_argument);
        }
    }
    SECTION("The longest accepted version is 64 characters")
    {
        const std::string longest{"1.2.3+" + std::string(58, 'x')};
        REQUIRE(longest.size() == 64);
        REQUIRE(parsed(longest).toString() == "1.2.3");
    }
    SECTION("The constructor agrees with parse")
    {
        REQUIRE(ClientVersion {"1.2.3+45"} == parsed("1.2.3"));
    }
    SECTION("Ordering is numeric, part by part")
    {
        // Not string order: 10 > 9.
        REQUIRE(parsed("1.10.0") > parsed("1.9.0"));
        REQUIRE(parsed("1.2.10") > parsed("1.2.9"));
        REQUIRE(parsed("10.0.0") > parsed("9.99.99"));
        // Major outranks minor outranks patch.
        REQUIRE(parsed("2.0.0") > parsed("1.99.99"));
        REQUIRE(parsed("1.3.0") > parsed("1.2.99"));
        REQUIRE(parsed("1.2.4") > parsed("1.2.3"));
        REQUIRE(parsed("1.2.3") >= parsed("1.2.3"));
        REQUIRE_FALSE(parsed("1.2.3") < parsed("1.2.3"));
    }
    SECTION("Suffixes do not affect ordering")
    {
        // A minimum of 1.2.3 admits every build of 1.2.3, pre-release
        // or not.
        REQUIRE(parsed("1.2.3-beta") == parsed("1.2.3"));
        REQUIRE(parsed("1.2.3+45") == parsed("1.2.3+46"));
        REQUIRE_FALSE(parsed("1.2.3-beta") < parsed("1.2.3"));
    }
}
