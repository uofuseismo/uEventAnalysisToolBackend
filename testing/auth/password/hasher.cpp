#include <cstddef>
#include <stdexcept>
#include <string>
#include <utility>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth::Password;

// Every test sticks to the interactive preset or below.  Moderate and
// sensitive are only ever parsed (needsRehash), never hashed, so the
// suite does not allocate 256 MiB or 1 GiB per call.

namespace
{

constexpr size_t MiB{1024UL*1024UL};

/// @brief The libsodium parameter block for an Argon2id hash,
///        e.g., $argon2id$v=19$m=65536,t=2,p=1$
std::string parameterBlock(const std::string &encodedHash)
{
    // $argon2id$v=19$m=...,t=...,p=...$salt$hash -> through the 4th $.
    size_t position{0};
    for (int i = 0; i < 3; ++i)
    {
        position = encodedHash.find('$', position + 1);
        if (position == std::string::npos){return {};}
    }
    return encodedHash.substr(0, position + 1);
}

}

TEST_CASE("UEventAnalysisToolBackend::Auth::Password::Hasher", "Hasher")
{
    const std::string password{"sam-i-am likes green eggs"};

    SECTION("Default options give an interactive Argon2id hash")
    {
        const Hasher hasher{HasherOptions{}};
        const auto hash = hasher.hash(password);
        REQUIRE(parameterBlock(hash) == "$argon2id$v=19$m=65536,t=2,p=1$");
        // The NUL padding from crypto_pwhash_STRBYTES is gone, so the
        // string is safe to hand straight to a TEXT column.
        REQUIRE(hash.find('\0') == std::string::npos);
        REQUIRE(hash.size() < 128);
    }
    SECTION("Options are carried into the hash")
    {
        HasherOptions options;
        options.setMemoryLimitInBytes(32*MiB);
        const Hasher hasher{options};
        REQUIRE(parameterBlock(hasher.hash(password))
                == "$argon2id$v=19$m=32768,t=2,p=1$");
    }
    SECTION("Salted: the same password hashes differently each time")
    {
        const Hasher hasher{HasherOptions{}};
        REQUIRE(hasher.hash(password) != hasher.hash(password));
    }
    SECTION("Empty and long passwords hash")
    {
        const Hasher hasher{HasherOptions{}};
        REQUIRE_FALSE(hasher.hash("").empty());
        REQUIRE_FALSE(hasher.hash(std::string(4096, 'x')).empty());
    }
    SECTION("The smallest memory limit the options accept still hashes")
    {
        // HasherOptions refuses anything libsodium would; this checks
        // the two agree at the boundary (crypto_pwhash_MEMLIMIT_MIN).
        HasherOptions options;
        options.setMemoryLimitInBytes(8192);
        const Hasher hasher{options};
        REQUIRE(parameterBlock(hasher.hash(password))
                == "$argon2id$v=19$m=8,t=2,p=1$");
    }
    SECTION("A hash made with the current options needs no rehash")
    {
        const Hasher hasher{HasherOptions{}};
        REQUIRE_FALSE(hasher.needsRehash(hasher.hash(password)));
    }
    SECTION("A hash made at a different cost needs a rehash")
    {
        HasherOptions cheap;
        cheap.setMemoryLimitInBytes(32*MiB);
        const auto cheapHash = Hasher{cheap}.hash(password);

        const Hasher interactive{HasherOptions{}};
        REQUIRE(interactive.needsRehash(cheapHash));

        HasherOptions moderate;
        moderate.setOperationsLimit(HasherOptions::OperationsLimit::Moderate);
        moderate.setMemoryLimitInBytes(256*MiB);
        REQUIRE(Hasher{moderate}.needsRehash(interactive.hash(password)));

        // Same memory, more passes is still a different cost.
        HasherOptions morePasses;
        morePasses.setOperationsLimit(
            HasherOptions::OperationsLimit::Sensitive);
        REQUIRE(Hasher{morePasses}.needsRehash(interactive.hash(password)));
    }
    SECTION("An unreadable hash throws")
    {
        const Hasher hasher{HasherOptions{}};
        REQUIRE_THROWS_AS(hasher.needsRehash(""), std::runtime_error);
        REQUIRE_THROWS_AS(hasher.needsRehash("hash-root"),
                          std::runtime_error);
        REQUIRE_THROWS_AS(hasher.needsRehash("$argon2id$v=19$garbage"),
                          std::runtime_error);
    }
    SECTION("Copy and move keep the options")
    {
        HasherOptions options;
        options.setMemoryLimitInBytes(32*MiB);
        Hasher hasher{options};
        const auto expected = "$argon2id$v=19$m=32768,t=2,p=1$";

        const Hasher copy{hasher};
        REQUIRE(parameterBlock(copy.hash(password)) == expected);

        Hasher assigned{HasherOptions{}};
        assigned = copy;
        REQUIRE(parameterBlock(assigned.hash(password)) == expected);

        const Hasher moved{std::move(hasher)};
        REQUIRE(parameterBlock(moved.hash(password)) == expected);

        Hasher moveAssigned{HasherOptions{}};
        moveAssigned = Hasher{copy};
        REQUIRE(parameterBlock(moveAssigned.hash(password)) == expected);
    }
}
