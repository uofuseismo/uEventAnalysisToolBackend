#include <cstddef>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth::Password;

namespace
{

constexpr size_t MiB{1024UL*1024UL};

/// @brief Writes an ini file that is removed when this goes out of scope.
class TemporaryIniFile
{
public:
    explicit TemporaryIniFile(const std::string &contents) :
        mPath{std::filesystem::temp_directory_path()
            / ("ueat-hasherOptions-" + std::to_string(sCounter++) + ".ini")}
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

}

TEST_CASE("UEventAnalysisToolBackend::Auth::Password::HasherOptions",
          "HasherOptions")
{
    SECTION("Defaults are libsodium's interactive preset")
    {
        const HasherOptions options;
        REQUIRE(options.getOperationsLimit()
                == HasherOptions::OperationsLimit::Interactive);
        REQUIRE(options.getMemoryLimitInBytes() == 64*MiB);
    }
    SECTION("Setters round trip")
    {
        HasherOptions options;
        options.setOperationsLimit(HasherOptions::OperationsLimit::Moderate);
        options.setMemoryLimitInBytes(256*MiB);
        REQUIRE(options.getOperationsLimit()
                == HasherOptions::OperationsLimit::Moderate);
        REQUIRE(options.getMemoryLimitInBytes() == 256*MiB);
        options.setOperationsLimit(HasherOptions::OperationsLimit::Sensitive);
        REQUIRE(options.getOperationsLimit()
                == HasherOptions::OperationsLimit::Sensitive);
    }
    SECTION("Memory limit must be at least 8 KiB")
    {
        HasherOptions options;
        REQUIRE_THROWS_AS(options.setMemoryLimitInBytes(0),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(options.setMemoryLimitInBytes(8191),
                          std::invalid_argument);
        // A rejected value leaves the previous one in place.
        REQUIRE(options.getMemoryLimitInBytes() == 64*MiB);
        options.setMemoryLimitInBytes(8192);
        REQUIRE(options.getMemoryLimitInBytes() == 8192);
    }
    SECTION("Copy and move")
    {
        HasherOptions options;
        options.setOperationsLimit(HasherOptions::OperationsLimit::Sensitive);
        options.setMemoryLimitInBytes(32*MiB);

        const HasherOptions copy{options};
        REQUIRE(copy.getOperationsLimit()
                == HasherOptions::OperationsLimit::Sensitive);
        REQUIRE(copy.getMemoryLimitInBytes() == 32*MiB);

        // The copy is deep: changing the original leaves it alone.
        options.setMemoryLimitInBytes(128*MiB);
        REQUIRE(copy.getMemoryLimitInBytes() == 32*MiB);

        HasherOptions assigned;
        assigned = copy;
        REQUIRE(assigned.getMemoryLimitInBytes() == 32*MiB);

        const HasherOptions moved{std::move(assigned)};
        REQUIRE(moved.getOperationsLimit()
                == HasherOptions::OperationsLimit::Sensitive);
        REQUIRE(moved.getMemoryLimitInBytes() == 32*MiB);

        HasherOptions moveAssigned;
        moveAssigned = HasherOptions{copy};
        REQUIRE(moveAssigned.getMemoryLimitInBytes() == 32*MiB);
    }
}

TEST_CASE("UEventAnalysisToolBackend::Auth::Password::HasherOptions::fromInitializationFile",
          "HasherOptions")
{
    SECTION("Missing file throws")
    {
        REQUIRE_THROWS_AS(
            HasherOptions::fromInitializationFile(
                std::filesystem::temp_directory_path()
              / "ueat-hasherOptions-does-not-exist.ini"),
            std::invalid_argument);
    }
    SECTION("Missing section gives the defaults")
    {
        const TemporaryIniFile ini{"[SomethingElse]\nkey = value\n"};
        const auto options = HasherOptions::fromInitializationFile(ini.path());
        REQUIRE(options.getOperationsLimit()
                == HasherOptions::OperationsLimit::Interactive);
        REQUIRE(options.getMemoryLimitInBytes() == 64*MiB);
    }
    SECTION("Values are read from the default section")
    {
        const TemporaryIniFile ini{
            "[PasswordHasherOptions]\n"
            "operationsLimit = moderate\n"
            "memoryLimitInMB = 256\n"};
        const auto options = HasherOptions::fromInitializationFile(ini.path());
        REQUIRE(options.getOperationsLimit()
                == HasherOptions::OperationsLimit::Moderate);
        REQUIRE(options.getMemoryLimitInBytes() == 256*MiB);
    }
    SECTION("Operations limit is case insensitive")
    {
        const TemporaryIniFile ini{
            "[PasswordHasherOptions]\noperationsLimit = SeNsItIvE\n"};
        const auto options = HasherOptions::fromInitializationFile(ini.path());
        REQUIRE(options.getOperationsLimit()
                == HasherOptions::OperationsLimit::Sensitive);
        // Memory limit was not given, so it stays at the default.
        REQUIRE(options.getMemoryLimitInBytes() == 64*MiB);
    }
    SECTION("A named section is honored, with or without a trailing dot")
    {
        const TemporaryIniFile ini{
            "[PasswordHasherOptions]\noperationsLimit = moderate\n"
            "[Hasher]\noperationsLimit = sensitive\nmemoryLimitInMB = 128\n"};
        for (const std::string section : {"Hasher", "Hasher."})
        {
            const auto options
                = HasherOptions::fromInitializationFile(ini.path(), section);
            REQUIRE(options.getOperationsLimit()
                    == HasherOptions::OperationsLimit::Sensitive);
            REQUIRE(options.getMemoryLimitInBytes() == 128*MiB);
        }
    }
    SECTION("Unknown operations limit throws")
    {
        const TemporaryIniFile ini{
            "[PasswordHasherOptions]\noperationsLimit = paranoid\n"};
        REQUIRE_THROWS_AS(HasherOptions::fromInitializationFile(ini.path()),
                          std::invalid_argument);
    }
    SECTION("Zero memory limit throws")
    {
        const TemporaryIniFile ini{
            "[PasswordHasherOptions]\nmemoryLimitInMB = 0\n"};
        REQUIRE_THROWS_AS(HasherOptions::fromInitializationFile(ini.path()),
                          std::invalid_argument);
    }
}
