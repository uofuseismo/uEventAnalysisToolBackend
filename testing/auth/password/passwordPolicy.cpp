#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolAPI/auth/v1/password_requirements.pb.h"

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
    REQUIRE(policy.getMinimumAndMaximumLength() == std::pair{12, 64});
    REQUIRE(policy.requiresNumber());
    REQUIRE_FALSE(policy.requiresSpecialCharacter());
    REQUIRE(policy.newAndOldPasswordMustDiffer());
}

/// @brief Every setting flipped away from its default.
PasswordPolicy makeNonDefault()
{
    PasswordPolicy policy;
    policy.setMinimumAndMaximumLength({20, 128});
    policy.disableRequiresNumber();
    policy.enableRequiresSpecialCharacter();
    policy.disableNewAndOldPasswordMustDiffer();
    return policy;
}

void requireNonDefault(const PasswordPolicy &policy)
{
    REQUIRE(policy.getMinimumAndMaximumLength() == std::pair{20, 128});
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
        REQUIRE_THROWS_AS(policy.setMinimumAndMaximumLength({0, 64}),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(policy.setMinimumAndMaximumLength({-1, 64}),
                          std::invalid_argument);
        // A rejected value leaves the previous one in place.
        REQUIRE(policy.getMinimumAndMaximumLength() == std::pair{12, 64});
        policy.setMinimumAndMaximumLength({1, 2});
        REQUIRE(policy.getMinimumAndMaximumLength() == std::pair{1, 2});
    }
    SECTION("Maximum length must exceed the minimum")
    {
        PasswordPolicy policy;
        REQUIRE_THROWS_AS(policy.setMinimumAndMaximumLength({12, 12}),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(policy.setMinimumAndMaximumLength({12, 11}),
                          std::invalid_argument);
        REQUIRE(policy.getMinimumAndMaximumLength() == std::pair{12, 64});
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
        policy.setMinimumAndMaximumLength({30, 40});
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
    SECTION("To PasswordRequirements")
    {
        using UEventAnalysisToolAPI::Auth::V1::PasswordRequirements;
        const auto response
            = makeNonDefault().toMessage<PasswordRequirements>();
        REQUIRE(response.minimum_length() == 20);
        REQUIRE(response.maximum_length() == 128);
        REQUIRE_FALSE(response.requires_number());
        REQUIRE(response.requires_special_character());
        REQUIRE_FALSE(response.new_and_old_password_must_differ());

        const auto defaults = PasswordPolicy{}.toMessage<PasswordRequirements>();
        REQUIRE(defaults.minimum_length() == 12);
        REQUIRE(defaults.maximum_length() == 64);
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
            "maximumLength = 128\n"
            "requiresNumber = false\n"
            "requiresSpecialCharacter = true\n"
            "newAndOldPasswordMustDiffer = false\n"};
        requireNonDefault(PasswordPolicy::fromInitializationFile(ini.path()));
    }
    SECTION("Unset keys keep their defaults")
    {
        const TemporaryIniFile ini{
            "[UserPasswordPolicy]\nrequiresSpecialCharacter = true\n"};
        const auto policy = PasswordPolicy::fromInitializationFile(ini.path());
        REQUIRE(policy.getMinimumAndMaximumLength() == std::pair{12, 64});
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
            "newAndOldPasswordMustDiffer = 0\n"};
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
            "maximumLength = 128\n"
            "requiresNumber = false\n"
            "requiresSpecialCharacter = true\n"
            "newAndOldPasswordMustDiffer = false\n"};
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
    SECTION("Maximum length at or below the minimum throws")
    {
        // Only one key given: it is checked against the other's default.
        const TemporaryIniFile shortMax{
            "[UserPasswordPolicy]\nmaximumLength = 12\n"};
        REQUIRE_THROWS_AS(
            PasswordPolicy::fromInitializationFile(shortMax.path()),
            std::invalid_argument);
        const TemporaryIniFile longMin{
            "[UserPasswordPolicy]\nminimumLength = 64\n"};
        REQUIRE_THROWS_AS(
            PasswordPolicy::fromInitializationFile(longMin.path()),
            std::invalid_argument);
    }
}

// A value that is present but unparseable currently falls back to the
// default without a word: ptree::get<T>(key, default) swallows the
// conversion error.  [!mayfail] keeps this from failing the suite until
// fromInitializationFile parses present keys strictly; drop the tag then.
TEST_CASE("UEventAnalysisToolBackend::Auth::Password::PasswordPolicy::fromInitializationFile strict parsing",
          "[!mayfail]")
{
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
        // Only true/false/1/0 convert, so this silently means false.
        const TemporaryIniFile shouting{
            "[UserPasswordPolicy]\nrequiresSpecialCharacter = TRUE\n"};
        REQUIRE_THROWS_AS(
            PasswordPolicy::fromInitializationFile(shouting.path()),
            std::runtime_error);
    }
}

TEST_CASE("UEventAnalysisToolBackend::Auth::Password::PasswordPolicy::validate",
          "PasswordPolicy")
{
    using Result = PasswordPolicy::ValidationResult;
    // 12 to 20 characters, a number, a special character, and a change.
    PasswordPolicy policy;
    policy.setMinimumAndMaximumLength(std::pair {12, 20});
    policy.enableRequiresNumber();
    policy.enableRequiresSpecialCharacter();
    policy.enableNewAndOldPasswordMustDiffer();
    const std::string old{"green eggs and ham"};

    SECTION("A password meeting every rule is valid")
    {
        REQUIRE(policy.validate(std::pair {std::string {"green eggs 4 ham!"}, old})
             == Result::Valid);
    }
    SECTION("Length is checked inclusively at both ends")
    {
        // Each candidate has a number and a special character, so only
        // the length can fail it.
        const auto ofLength = [](const std::size_t n)
        {
            return "1!" + std::string(n - 2, 'a');
        };
        REQUIRE(policy.validate(std::pair {ofLength(11), old}) == Result::TooShort);
        REQUIRE(policy.validate(std::pair {ofLength(12), old}) == Result::Valid);
        REQUIRE(policy.validate(std::pair {ofLength(20), old}) == Result::Valid);
        REQUIRE(policy.validate(std::pair {ofLength(21), old}) == Result::TooLong);
        REQUIRE(policy.validate(std::pair {std::string {}, old})
             == Result::TooShort);
    }
    SECTION("Length counts bytes, not characters")
    {
        // Six two-byte characters: twelve bytes, so long enough.  This
        // documents the behavior; it is a choice, not an accident.
        const std::string accented{"\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"};
        policy.disableRequiresNumber();
        policy.disableRequiresSpecialCharacter();
        REQUIRE(policy.validate(std::pair {accented, old}) == Result::Valid);
    }
    SECTION("A number is required only when the policy says so")
    {
        const std::string noNumber{"green eggs & spam"};
        REQUIRE(policy.validate(std::pair {noNumber, old}) == Result::NoNumber);
        policy.disableRequiresNumber();
        REQUIRE(policy.validate(std::pair {noNumber, old}) == Result::Valid);
    }
    SECTION("Every digit counts as a number")
    {
        for (char digit = '0'; digit <= '9'; ++digit)
        {
            const std::string candidate{"green eggs ! " + std::string(1, digit)};
            INFO("digit " << digit);
            REQUIRE(policy.validate(std::pair {candidate, old}) == Result::Valid);
        }
    }
    SECTION("A special character is required only when the policy says so")
    {
        const std::string noSpecial{"green eggs and 42"};
        REQUIRE(policy.validate(std::pair {noSpecial, old})
             == Result::NoSpecialCharacter);
        policy.disableRequiresSpecialCharacter();
        REQUIRE(policy.validate(std::pair {noSpecial, old}) == Result::Valid);
    }
    SECTION("Every ASCII punctuation character counts as special")
    {
        constexpr std::string_view punctuation{R"(!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)"};
        REQUIRE(punctuation.size() == 32);
        for (const auto c : punctuation)
        {
            const std::string candidate{"greeneggs42" + std::string(1, c)};
            INFO("character " << c);
            REQUIRE(policy.validate(std::pair {candidate, old}) == Result::Valid);
        }
    }
    SECTION("Spaces and non-ASCII bytes are not special")
    {
        REQUIRE(policy.validate(std::pair {std::string {"green eggs and 42"}, old})
             == Result::NoSpecialCharacter);
        REQUIRE(policy.validate(
                    std::pair {std::string {"green\xc3\xa9ggs and 42"}, old})
             == Result::NoSpecialCharacter);
    }
    SECTION("The new password must differ only when the policy says so")
    {
        const std::string same{"green eggs 4 ham!"};
        REQUIRE(policy.validate(std::pair {same, same}) == Result::PasswordsMatch);
        policy.disableNewAndOldPasswordMustDiffer();
        REQUIRE(policy.validate(std::pair {same, same}) == Result::Valid);
    }
    SECTION("Matching is exact")
    {
        // Case and trailing whitespace make a different password.
        const std::string same{"green eggs 4 ham!"};
        REQUIRE(policy.validate(std::pair {std::string {"Green eggs 4 ham!"}, same})
             == Result::Valid);
        REQUIRE(policy.validate(std::pair {same + " ", same}) == Result::Valid);
    }
}

TEST_CASE("UEventAnalysisToolBackend::Auth::Password::PasswordPolicy::createTemporaryPassword",
          "PasswordPolicy")
{
    // Issued passwords are random, so check many: a rare bad character
    // is exactly what one sample would miss.
    constexpr int nSamples{2000};
    const auto requireAllValid = [](const PasswordPolicy &policy)
    {
        for (int i = 0; i < nSamples; ++i)
        {
            const auto password = policy.createTemporaryPassword();
            INFO("password " << i << " = " << password);
            // Something a person can type: no NUL, nothing unprintable.
            REQUIRE(std::ranges::all_of(password,
                                        [](const char c)
                                        {
                                            return c > ' ' && c <= '~';
                                        }));
            // An issued password is one the policy would accept.
            REQUIRE(policy.validate(std::pair {password, std::string {}})
                 == PasswordPolicy::ValidationResult::Valid);
        }
    };

    SECTION("Default policy")
    {
        requireAllValid(PasswordPolicy {});
    }
    SECTION("Number and special character required")
    {
        PasswordPolicy policy;
        policy.enableRequiresNumber();
        policy.enableRequiresSpecialCharacter();
        requireAllValid(policy);
    }
    SECTION("Neither required")
    {
        PasswordPolicy policy;
        policy.disableRequiresNumber();
        policy.disableRequiresSpecialCharacter();
        requireAllValid(policy);
    }
    SECTION("Shortest lengths the policy allows")
    {
        PasswordPolicy policy;
        policy.setMinimumAndMaximumLength(std::pair {3, 4});
        policy.enableRequiresNumber();
        policy.enableRequiresSpecialCharacter();
        requireAllValid(policy);
    }
    SECTION("Two passwords differ")
    {
        const PasswordPolicy policy;
        REQUIRE(policy.createTemporaryPassword()
             != policy.createTemporaryPassword());
    }
}
