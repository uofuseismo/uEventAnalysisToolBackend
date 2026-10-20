#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolAPI/auth/v1/password_requirements_response.pb.h"

using namespace UEventAnalysisToolBackend::Auth::Password;

namespace
{

/// @brief Writes an ini file that is removed when this goes out of scope.
class TemporaryIniFile
{
public:
    explicit TemporaryIniFile(const std::string &contents) :
        mPath{std::filesystem::temp_directory_path()
            / ("ueat-passwordPolicy-" + std::to_string(sCounter++) + ".ini")}
    {
        std::ofstream file{mPath};
        file << contents;
    }
    ~TemporaryIniFile()
    {
        std::error_code error;
        std::filesystem::remove(mPath, error);
    }
    TemporaryIniFile(const TemporaryIniFile &) = delete;
    TemporaryIniFile& operator=(const TemporaryIniFile &) = delete;
    [[nodiscard]] const std::filesystem::path &path() const noexcept
    {
        return mPath;
    }
private:
    static inline int sCounter{0};
    std::filesystem::path mPath;
};

/// @brief The defaults, spelled out once.
void requireDefaults(const PasswordPolicy &policy)
{
    REQUIRE(policy.getMinimumLength() == 12);
    REQUIRE(policy.requiresNumber());
    REQUIRE_FALSE(policy.requiresSpecialCharacter());
    REQUIRE(policy.newAndOldPasswordMustDiffer());
}

/// @brief Every setting flipped away from its default.
PasswordPolicy makeNonDefault()
{
    PasswordPolicy policy;
    policy.setMinimumLength(20);
    policy.disableRequiresNumber();
    policy.enableRequiresSpecialCharacter();
    policy.disableNewAndOldPasswordMustDiffer();
    return policy;
}

void requireNonDefault(const PasswordPolicy &policy)
{
    REQUIRE(policy.getMinimumLength() == 20);
    REQUIRE_FALSE(policy.requiresNumber());
    REQUIRE(policy.requiresSpecialCharacter());
    REQUIRE_FALSE(policy.newAndOldPasswordMustDiffer());
}

}

TEST_CASE("UEventAnalysisToolBackend::Auth::Password::PasswordPolicy",
          "PasswordPolicy")
{
    SECTION("Defaults")
    {
        const PasswordPolicy policy;
        requireDefaults(policy);
    }
    SECTION("Minimum length must be positive")
    {
        PasswordPolicy policy;
        REQUIRE_THROWS_AS(policy.setMinimumLength(0), std::invalid_argument);
        REQUIRE_THROWS_AS(policy.setMinimumLength(-1), std::invalid_argument);
        // A rejected value leaves the previous one in place.
        REQUIRE(policy.getMinimumLength() == 12);
        policy.setMinimumLength(1);
        REQUIRE(policy.getMinimumLength() == 1);
    }
    SECTION("Toggles round trip")
    {
        PasswordPolicy policy;
        requireNonDefault(makeNonDefault());

        policy.disableRequiresNumber();
        REQUIRE_FALSE(policy.requiresNumber());
        policy.enableRequiresNumber();
        REQUIRE(policy.requiresNumber());

        policy.enableRequiresSpecialCharacter();
        REQUIRE(policy.requiresSpecialCharacter());
        policy.disableRequiresSpecialCharacter();
        REQUIRE_FALSE(policy.requiresSpecialCharacter());

        policy.disableNewAndOldPasswordMustDiffer();
        REQUIRE_FALSE(policy.newAndOldPasswordMustDiffer());
        policy.enableNewAndOldPasswordMustDiffer();
        REQUIRE(policy.newAndOldPasswordMustDiffer());
    }
    SECTION("Copy and move")
    {
        auto policy = makeNonDefault();

        const PasswordPolicy copy{policy};
        requireNonDefault(copy);

        // The copy is deep: changing the original leaves it alone.
        policy.setMinimumLength(30);
        policy.enableRequiresNumber();
        requireNonDefault(copy);

        PasswordPolicy assigned;
        assigned = copy;
        requireNonDefault(assigned);

        const PasswordPolicy moved{std::move(assigned)};
        requireNonDefault(moved);

        PasswordPolicy moveAssigned;
        moveAssigned = PasswordPolicy{copy};
        requireNonDefault(moveAssigned);
    }
    SECTION("To PasswordRequirementsResponse")
    {
        const auto policy = makeNonDefault();
        const auto response
            = policy.toMessage<UEventAnalysisToolAPI::Auth::V1::PasswordRequirementsResponse>
              ("request-42");
        REQUIRE(response.identifier() == "request-42");
        REQUIRE(response.minimum_length() == 20);
        REQUIRE_FALSE(response.requires_number());
        REQUIRE(response.requires_special_character());
        REQUIRE_FALSE(response.new_and_old_password_must_differ());

        const auto defaults
            = PasswordPolicy{}.toMessage<UEventAnalysisToolAPI::Auth::V1::PasswordRequirementsResponse>
              ("");
        REQUIRE(defaults.identifier().empty());
        REQUIRE(defaults.minimum_length() == 12);
        REQUIRE(defaults.requires_number());
        REQUIRE_FALSE(defaults.requires_special_character());
        REQUIRE(defaults.new_and_old_password_must_differ());
    }
}

TEST_CASE("UEventAnalysisToolBackend::Auth::Password::PasswordPolicy::fromInitializationFile",
          "PasswordPolicy")
{
    SECTION("Missing file throws")
    {
        REQUIRE_THROWS_AS(
            PasswordPolicy::fromInitializationFile(
                std::filesystem::temp_directory_path()
              / "ueat-passwordPolicy-does-not-exist.ini"),
            std::invalid_argument);
    }
    SECTION("Missing section gives the defaults")
    {
        const TemporaryIniFile ini{"[SomethingElse]\nminimumLength = 30\n"};
        requireDefaults(PasswordPolicy::fromInitializationFile(ini.path()));
    }
    SECTION("Values are read from the default section")
    {
        const TemporaryIniFile ini{
            "[UserPasswordPolicy]\n"
            "minimumLength = 20\n"
            "requiresNumber = false\n"
            "requiresSpecialCharacter = true\n"
            "newAndOldMustBeDifferent = false\n"};
        requireNonDefault(PasswordPolicy::fromInitializationFile(ini.path()));
    }
    SECTION("Unset keys keep their defaults")
    {
        const TemporaryIniFile ini{
            "[UserPasswordPolicy]\nrequiresSpecialCharacter = true\n"};
        const auto policy = PasswordPolicy::fromInitializationFile(ini.path());
        REQUIRE(policy.getMinimumLength() == 12);
        REQUIRE(policy.requiresNumber());
        REQUIRE(policy.requiresSpecialCharacter());
        REQUIRE(policy.newAndOldPasswordMustDiffer());
    }
    SECTION("Booleans may be written as 1 and 0")
    {
        const TemporaryIniFile ini{
            "[UserPasswordPolicy]\n"
            "requiresNumber = 0\n"
            "requiresSpecialCharacter = 1\n"
            "newAndOldMustBeDifferent = 0\n"};
        const auto policy = PasswordPolicy::fromInitializationFile(ini.path());
        REQUIRE_FALSE(policy.requiresNumber());
        REQUIRE(policy.requiresSpecialCharacter());
        REQUIRE_FALSE(policy.newAndOldPasswordMustDiffer());
    }
    SECTION("A named section is honored, with or without a trailing dot")
    {
        const TemporaryIniFile ini{
            "[UserPasswordPolicy]\nminimumLength = 30\n"
            "[Policy]\n"
            "minimumLength = 20\n"
            "requiresNumber = false\n"
            "requiresSpecialCharacter = true\n"
            "newAndOldMustBeDifferent = false\n"};
        for (const std::string section : {"Policy", "Policy."})
        {
            requireNonDefault(
                PasswordPolicy::fromInitializationFile(ini.path(), section));
        }
    }
    SECTION("Non-positive minimum length throws")
    {
        const TemporaryIniFile ini{"[UserPasswordPolicy]\nminimumLength = 0\n"};
        REQUIRE_THROWS_AS(PasswordPolicy::fromInitializationFile(ini.path()),
                          std::invalid_argument);
    }
    SECTION("Unparseable values throw")
    {
        // Boost's ptree_bad_data, which is a std::runtime_error.
        const TemporaryIniFile badBool{
            "[UserPasswordPolicy]\nrequiresNumber = maybe\n"};
        REQUIRE_THROWS_AS(PasswordPolicy::fromInitializationFile(badBool.path()),
                          std::runtime_error);
        const TemporaryIniFile badLength{
            "[UserPasswordPolicy]\nminimumLength = twelve\n"};
        REQUIRE_THROWS_AS(
            PasswordPolicy::fromInitializationFile(badLength.path()),
            std::runtime_error);
    }
}
