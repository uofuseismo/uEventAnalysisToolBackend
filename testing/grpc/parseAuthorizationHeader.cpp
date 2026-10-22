#include <format>
#include <string>
#include <utility>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <grpcpp/support/status.h>
#include <grpcpp/support/string_ref.h>
#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

// The base64 fixtures were made with `printf '%s' '<text>' | base64 -w0`.

namespace
{

/// @brief Every failure should look the same to the client.
template<typename T>
void requireUnauthenticated(const T &result)
{
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().error_code() == grpc::StatusCode::UNAUTHENTICATED);
    REQUIRE_FALSE(result.error().error_message().empty());
}

[[nodiscard]] auto basic(const std::string &header)
{
    return authorizationHeaderToUserNameAndPassword(grpc::string_ref{header});
}

[[nodiscard]] auto bearer(const std::string &header)
{
    return authorizationHeaderToToken(grpc::string_ref{header});
}

}

TEST_CASE("UEventAnalysisToolBackend::GRPC::authorizationHeaderToUserNameAndPassword",
          "[parseAuthorizationHeader]")
{
    // sam-i-am:green eggs and ham
    const std::string credentials{"c2FtLWktYW06Z3JlZW4gZWdncyBhbmQgaGFt"};
    const std::pair<std::string, std::string>
        expected{"sam-i-am", "green eggs and ham"};

    SECTION("Valid credentials")
    {
        const auto result = basic("Basic " + credentials);
        REQUIRE(result.has_value());
        REQUIRE(*result == expected);
    }
    SECTION("Scheme is case-insensitive")
    {
        for (const std::string &scheme : {"basic", "BASIC", "bAsIc"})
        {
            INFO(scheme);
            const auto result = basic(std::format("{} {}", scheme, credentials));
            REQUIRE(result.has_value());
            REQUIRE(*result == expected);
        }
    }
    SECTION("Surrounding and separating whitespace is ignored")
    {
        for (const std::string &header : {"  Basic " + credentials + "  ",
                                         "Basic\t" + credentials,
                                         "Basic    " + credentials,
                                         "\tBasic \t " + credentials + "\r\n"})
        {
            INFO(header);
            const auto result = basic(header);
            REQUIRE(result.has_value());
            REQUIRE(*result == expected);
        }
    }
    SECTION("Only the first colon separates user from password")
    {
        // sam-i-am:pass:with:colons
        const auto result = basic("Basic c2FtLWktYW06cGFzczp3aXRoOmNvbG9ucw==");
        REQUIRE(result.has_value());
        REQUIRE(result->first == "sam-i-am");
        REQUIRE(result->second == "pass:with:colons");
    }
    SECTION("Padded base64 decodes")
    {
        // ab:c
        const auto result = basic("Basic YWI6Yw==");
        REQUIRE(result.has_value());
        REQUIRE(result->first == "ab");
        REQUIRE(result->second == "c");
    }
    SECTION("Empty password is passed through")
    {
        // sam-i-am:
        const auto result = basic("Basic c2FtLWktYW06");
        REQUIRE(result.has_value());
        REQUIRE(result->first == "sam-i-am");
        REQUIRE(result->second.empty());
    }
    SECTION("Absent credentials")
    {
        requireUnauthenticated(basic(""));
        requireUnauthenticated(basic("   \t "));
    }
    SECTION("Scheme without credentials")
    {
        requireUnauthenticated(basic("Basic"));
        requireUnauthenticated(basic("Basic    "));
        requireUnauthenticated(basic("Basic" + credentials));
    }
    SECTION("Other schemes are rejected")
    {
        requireUnauthenticated(basic("Bearer " + credentials));
        requireUnauthenticated(basic("Basics " + credentials));
        requireUnauthenticated(basic("Digest " + credentials));
    }
    SECTION("Bad base64 is rejected")
    {
        requireUnauthenticated(basic("Basic !!!!"));
        requireUnauthenticated(basic("Basic " + credentials + "!"));
        requireUnauthenticated(basic("Basic " + credentials + "==junk"));
        // ab:c without its padding
        requireUnauthenticated(basic("Basic YWI6Yw"));
        // URL-safe alphabet is not the standard one
        requireUnauthenticated(basic("Basic -_-_"));
        // Spaces inside the credentials
        requireUnauthenticated(basic("Basic YTpi YTpi"));
    }
    SECTION("Decoded credentials without a colon are rejected")
    {
        // no colon here
        requireUnauthenticated(basic("Basic bm8gY29sb24gaGVyZQ=="));
    }
}

TEST_CASE("UEventAnalysisToolBackend::GRPC::authorizationHeaderToToken",
          "[parseAuthorizationHeader]")
{
    const std::string token{"aaaa.bbbb.cccc"};

    SECTION("Valid token")
    {
        const auto result = bearer("Bearer " + token);
        REQUIRE(result.has_value());
        REQUIRE(*result == token);
    }
    SECTION("Scheme is case-insensitive")
    {
        for (const std::string &scheme : {"bearer", "BEARER", "bEaReR"})
        {
            INFO(scheme);
            const auto result = bearer(std::format("{} {}", scheme, token));
            REQUIRE(result.has_value());
            REQUIRE(*result == token);
        }
    }
    SECTION("Surrounding and separating whitespace is ignored")
    {
        for (const std::string &header : {"  Bearer " + token + "  ",
                                         "Bearer\t" + token,
                                         "Bearer    " + token,
                                         "\tBearer \t " + token + "\r\n"})
        {
            INFO(header);
            const auto result = bearer(header);
            REQUIRE(result.has_value());
            REQUIRE(*result == token);
        }
    }
    SECTION("Token case is preserved")
    {
        const std::string mixed{"AbC.dEf.GhI"};
        const auto result = bearer("Bearer " + mixed);
        REQUIRE(result.has_value());
        REQUIRE(*result == mixed);
    }
    SECTION("Absent credentials")
    {
        requireUnauthenticated(bearer(""));
        requireUnauthenticated(bearer("   \t "));
    }
    SECTION("Scheme without a token")
    {
        requireUnauthenticated(bearer("Bearer"));
        requireUnauthenticated(bearer("Bearer    "));
        requireUnauthenticated(bearer("Bearer" + token));
    }
    SECTION("Other schemes are rejected")
    {
        // a:b
        requireUnauthenticated(bearer("Basic YTpi"));
        requireUnauthenticated(bearer("Bearers " + token));
        requireUnauthenticated(bearer("Token " + token));
    }
}

// Pending: these document checks not yet in the parser.  Drop [!mayfail]
// once they are.
TEST_CASE("UEventAnalysisToolBackend::GRPC::parseAuthorizationHeader stricter checks",
          "[parseAuthorizationHeader][!mayfail]")
{
    SECTION("A token with whitespace inside is rejected")
    {
        requireUnauthenticated(bearer("Bearer aaaa.bb bb.cccc"));
    }
    SECTION("A user name with control characters is rejected")
    {
        // sam<TAB>i-am:x
        requireUnauthenticated(basic("Basic c2FtCWktYW06eA=="));
        // sam<NUL>i-am:x
        requireUnauthenticated(basic("Basic c2FtAGktYW06eA=="));
        // sam-i-am<DEL>:x
        requireUnauthenticated(basic("Basic c2FtLWktYW1/Ong="));
    }
    SECTION("A password may still contain control characters")
    {
        // sam-i-am:pass<TAB>word
        const auto result = basic("Basic c2FtLWktYW06cGFzcwl3b3Jk");
        REQUIRE(result.has_value());
        REQUIRE(result->second == "pass\tword");
    }
}
