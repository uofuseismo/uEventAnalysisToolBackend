#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include "uEventAnalysisToolBackend/grpc/grpcServerOptions.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

namespace
{

/// @brief Writes a file that is removed when this goes out of scope.
class TemporaryFile
{
public:
    TemporaryFile(const std::string &contents, // NOLINT(bugprone-easily-swappable-parameters)
                  const std::string &extension) :
        mPath{std::filesystem::temp_directory_path()
            / ("ueat-grpcServerOptions-" + std::to_string(sCounter++)
             + extension)}
    {
        std::ofstream file{mPath};
        file << contents;
    }
    ~TemporaryFile()
    {
        std::error_code error;
        std::filesystem::remove(mPath, error);
    }
    TemporaryFile(const TemporaryFile &) = delete;
    TemporaryFile& operator=(const TemporaryFile &) = delete;
    [[nodiscard]] const std::filesystem::path &path() const noexcept
    {
        return mPath;
    }
private:
    static inline int sCounter{0};
    std::filesystem::path mPath;
};

/// @brief An ini file with a [GRPCServer] section holding these lines.
TemporaryFile makeIni(const std::string &lines)
{
    return TemporaryFile{"[GRPCServer]\n" + lines, ".ini"};
}

/// @brief The test certificate or key, as readSecretFile would return it.
std::string loadTrimmed(const std::string &fileName)
{
    const auto path = std::filesystem::path{TESTING_DATA_DIR}/"keys"/fileName;
    const std::ifstream file{path};
    std::stringstream stream;
    stream << file.rdbuf();
    const auto contents = stream.str();
    const auto first = contents.find_first_not_of(" \t\r\n");
    const auto last = contents.find_last_not_of(" \t\r\n");
    return contents.substr(first, last - first + 1);
}

std::string keyPath(const std::string &fileName)
{
    return (std::filesystem::path{TESTING_DATA_DIR}/"keys"/fileName).string();
}

void requireDefaults(const GRPCServerOptions &options)
{
    REQUIRE(options.getHost() == "localhost");
    REQUIRE(options.getPort() == 50000);
    REQUIRE_FALSE(options.hasServerCertificate());
    REQUIRE_FALSE(options.hasServerKey());
    REQUIRE_FALSE(options.getClientCertificate().has_value());
    REQUIRE_FALSE(options.isReflectionEnabled());
    REQUIRE(options.getMaximumRequestMessageSizeInBytes() == 65536);
    REQUIRE(options.getMaximumConnectionAge() == std::chrono::seconds {180});
    REQUIRE(options.getMaximumConnectionAgeGracePeriod()
            == std::chrono::seconds {2});
    REQUIRE(options.getMaximumRequestIdentifierSizeInBytes() == 128);
}

}

TEST_CASE("UEventAnalysisToolBackend::GRPC::GRPCServerOptions",
          "GRPCServerOptions")
{
    SECTION("Defaults")
    {
        const GRPCServerOptions options;
        requireDefaults(options);
        REQUIRE_THROWS_AS(options.getServerCertificate(), std::runtime_error);
        REQUIRE_THROWS_AS(options.getServerKey(), std::runtime_error);
    }
    SECTION("Host")
    {
        GRPCServerOptions options;
        options.setHost("machine.domain.com");
        REQUIRE(options.getHost() == "machine.domain.com");
        // Whitespace anywhere is stripped, not just at the ends.
        options.setHost("  machine. domain.com\n");
        REQUIRE(options.getHost() == "machine.domain.com");
        REQUIRE_THROWS_AS(options.setHost(""), std::invalid_argument);
        REQUIRE_THROWS_AS(options.setHost(" \t "), std::invalid_argument);
        REQUIRE(options.getHost() == "machine.domain.com");
    }
    SECTION("Port")
    {
        GRPCServerOptions options;
        options.setPort(443);
        REQUIRE(options.getPort() == 443);
        options.setPort(65535);
        REQUIRE(options.getPort() == 65535);
        REQUIRE_THROWS_AS(options.setPort(0), std::invalid_argument);
        REQUIRE(options.getPort() == 65535);
    }
    SECTION("Server certificate and key")
    {
        GRPCServerOptions options;
        REQUIRE_THROWS_AS(options.setServerCertificate(""),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(options.setServerKey(""), std::invalid_argument);
        REQUIRE_FALSE(options.hasServerCertificate());
        REQUIRE_FALSE(options.hasServerKey());

        options.setServerCertificate("certificate");
        REQUIRE(options.hasServerCertificate());
        REQUIRE_FALSE(options.hasServerKey());
        REQUIRE(options.getServerCertificate() == "certificate");

        options.setServerKey("key");
        REQUIRE(options.hasServerKey());
        REQUIRE(options.getServerKey() == "key");
    }
    SECTION("Client certificate")
    {
        GRPCServerOptions options;
        REQUIRE_THROWS_AS(options.setClientCertificate(""),
                          std::invalid_argument);
        REQUIRE_FALSE(options.getClientCertificate().has_value());
        options.setClientCertificate("client");
        REQUIRE(options.getClientCertificate() == "client");
    }
    SECTION("Reflection")
    {
        GRPCServerOptions options;
        options.enableReflection();
        REQUIRE(options.isReflectionEnabled());
        options.disableReflection();
        REQUIRE_FALSE(options.isReflectionEnabled());
    }
    SECTION("Maximum request message size must be positive")
    {
        GRPCServerOptions options;
        options.setMaximumRequestMessageSizeInBytes(1);
        REQUIRE(options.getMaximumRequestMessageSizeInBytes() == 1);
        REQUIRE_THROWS_AS(options.setMaximumRequestMessageSizeInBytes(0),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(options.setMaximumRequestMessageSizeInBytes(-1),
                          std::invalid_argument);
        REQUIRE(options.getMaximumRequestMessageSizeInBytes() == 1);
    }
    SECTION("Maximum connection age must be positive")
    {
        GRPCServerOptions options;
        options.setMaximumConnectionAge(std::chrono::milliseconds {1});
        REQUIRE(options.getMaximumConnectionAge() == std::chrono::milliseconds {1});
        REQUIRE_THROWS_AS(options.setMaximumConnectionAge(std::chrono::milliseconds {0}),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(options.setMaximumConnectionAge(-std::chrono::milliseconds {1}),
                          std::invalid_argument);
        REQUIRE(options.getMaximumConnectionAge() == std::chrono::milliseconds {1});
    }
    SECTION("Grace period may be zero but not negative")
    {
        GRPCServerOptions options;
        options.setMaximumConnectionAgeGracePeriod(std::chrono::milliseconds {0});
        REQUIRE(options.getMaximumConnectionAgeGracePeriod() == std::chrono::milliseconds {0});
        REQUIRE_THROWS_AS(options.setMaximumConnectionAgeGracePeriod(-std::chrono::milliseconds {1}),
                          std::invalid_argument);
        REQUIRE(options.getMaximumConnectionAgeGracePeriod() == std::chrono::milliseconds {0});
    }
    SECTION("Maximum request identifier size is in [1, 8192]")
    {
        GRPCServerOptions options;
        options.setMaximumRequestIdentifierSizeInBytes(1);
        REQUIRE(options.getMaximumRequestIdentifierSizeInBytes() == 1);
        options.setMaximumRequestIdentifierSizeInBytes(8192);
        REQUIRE(options.getMaximumRequestIdentifierSizeInBytes() == 8192);
        REQUIRE_THROWS_AS(options.setMaximumRequestIdentifierSizeInBytes(0),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(options.setMaximumRequestIdentifierSizeInBytes(8193),
                          std::invalid_argument);
        REQUIRE(options.getMaximumRequestIdentifierSizeInBytes() == 8192);
    }
    SECTION("Copy and move")
    {
        GRPCServerOptions options;
        options.setHost("machine.domain.com");
        options.setPort(443);
        options.setServerCertificate("certificate");
        options.setServerKey("key");
        options.setClientCertificate("client");
        options.enableReflection();
        options.setMaximumRequestMessageSizeInBytes(1024);
        options.setMaximumConnectionAge(std::chrono::seconds {10});
        options.setMaximumConnectionAgeGracePeriod(std::chrono::seconds {1});
        options.setMaximumRequestIdentifierSizeInBytes(64);

        const auto requireCopied = [](const GRPCServerOptions &copy)
        {
            REQUIRE(copy.getHost() == "machine.domain.com");
            REQUIRE(copy.getPort() == 443);
            REQUIRE(copy.getServerCertificate() == "certificate");
            REQUIRE(copy.getServerKey() == "key");
            REQUIRE(copy.getClientCertificate() == "client");
            REQUIRE(copy.isReflectionEnabled());
            REQUIRE(copy.getMaximumRequestMessageSizeInBytes() == 1024);
            REQUIRE(copy.getMaximumConnectionAge() == std::chrono::seconds {10});
            REQUIRE(copy.getMaximumConnectionAgeGracePeriod() == std::chrono::seconds {1});
            REQUIRE(copy.getMaximumRequestIdentifierSizeInBytes() == 64);
        };

        const GRPCServerOptions copy{options};
        requireCopied(copy);

        // The copy is deep: changing the original leaves it alone.
        options.setHost("elsewhere");
        options.disableReflection();
        requireCopied(copy);

        GRPCServerOptions assigned;
        assigned = copy;
        requireCopied(assigned);

        const GRPCServerOptions moved{std::move(assigned)};
        requireCopied(moved);

        GRPCServerOptions moveAssigned;
        moveAssigned = GRPCServerOptions{copy};
        requireCopied(moveAssigned);
    }
}

TEST_CASE("UEventAnalysisToolBackend::GRPC::GRPCServerOptions::fromInitializationFile",
          "GRPCServerOptions")
{
    SECTION("Missing file throws")
    {
        REQUIRE_THROWS_AS(
            GRPCServerOptions::fromInitializationFile(std::filesystem::temp_directory_path()
                                 / "ueat-grpcServerOptions-missing.ini"),
            std::invalid_argument);
    }
    SECTION("Missing section gives the defaults")
    {
        const TemporaryFile ini{"[SomethingElse]\nport = 443\n", ".ini"};
        requireDefaults(GRPCServerOptions::fromInitializationFile(ini.path()));
    }
    SECTION("Every value is read")
    {
        const auto ini = makeIni(
            "host = machine.domain.com\n"
            "port = 443\n"
            "enableReflection = true\n"
            "maximumRequestMessageSizeInBytes = 1024\n"
            "maximumRequestIdentifierSizeInBytes = 64\n"
            "maximumConnectionAgeInMilliSeconds = 10000\n"
            "maximumConnectionAgeGracePeriodInMilliSeconds = 0\n");
        const auto options = GRPCServerOptions::fromInitializationFile(ini.path());
        REQUIRE(options.getHost() == "machine.domain.com");
        REQUIRE(options.getPort() == 443);
        REQUIRE(options.isReflectionEnabled());
        REQUIRE(options.getMaximumRequestMessageSizeInBytes() == 1024);
        REQUIRE(options.getMaximumRequestIdentifierSizeInBytes() == 64);
        REQUIRE(options.getMaximumConnectionAge() == std::chrono::seconds {10});
        REQUIRE(options.getMaximumConnectionAgeGracePeriod() == std::chrono::milliseconds {0});
        REQUIRE_FALSE(options.hasServerCertificate());
        REQUIRE_FALSE(options.hasServerKey());
    }
    SECTION("A named section is honored, with or without a trailing dot")
    {
        const TemporaryFile ini{"[GRPCServer]\nport = 443\n"
                                "[Frontend]\nport = 8443\n", ".ini"};
        for (const std::string section : {"Frontend", "Frontend."})
        {
            REQUIRE(GRPCServerOptions::fromInitializationFile(ini.path(), section).getPort()
                    == 8443);
        }
    }
    SECTION("Unparseable values throw")
    {
        for (const std::string line : {"port = http",
                                       "port = 8080x",
                                       "port = 70000",
                                       "port =",
                                       "enableReflection = maybe",
                                       "maximumRequestMessageSizeInBytes = big",
                                       "maximumConnectionAgeInMilliSeconds = 1.5"})
        {
            const auto ini = makeIni(line + "\n");
            INFO(line);
            REQUIRE_THROWS_AS(GRPCServerOptions::fromInitializationFile(ini.path()),
                              std::invalid_argument);
        }
    }
    SECTION("Out of range values throw")
    {
        for (const std::string line : {"host =",
                                       "port = 0",
                                       "maximumRequestMessageSizeInBytes = 0",
                                       "maximumRequestIdentifierSizeInBytes = 0",
                                       "maximumRequestIdentifierSizeInBytes = 8193",
                                       "maximumConnectionAgeInMilliSeconds = 0",
                                       "maximumConnectionAgeGracePeriodInMilliSeconds = -1"})
        {
            const auto ini = makeIni(line + "\n");
            INFO(line);
            REQUIRE_THROWS_AS(GRPCServerOptions::fromInitializationFile(ini.path()),
                              std::invalid_argument);
        }
    }
    SECTION("Server key and certificate inline")
    {
        const auto ini = makeIni("serverKey = the-key\n"
                                 "serverCertificate = the-certificate\n");
        const auto options = GRPCServerOptions::fromInitializationFile(ini.path());
        REQUIRE(options.getServerKey() == "the-key");
        REQUIRE(options.getServerCertificate() == "the-certificate");
    }
    SECTION("Server key and certificate from files")
    {
        const auto ini = makeIni(
            "serverKeyFile = " + keyPath("self-signed-test.key") + "\n"
          + "serverCertificateFile = " + keyPath("self-signed-test.crt") + "\n");
        const auto options = GRPCServerOptions::fromInitializationFile(ini.path());
        REQUIRE(options.getServerKey() == loadTrimmed("self-signed-test.key"));
        REQUIRE(options.getServerCertificate()
                == loadTrimmed("self-signed-test.crt"));
    }
    SECTION("Inline and file forms may be mixed across key and certificate")
    {
        const auto ini = makeIni(
            "serverKey = the-key\n"
            "serverCertificateFile = " + keyPath("self-signed-test.crt") + "\n");
        const auto options = GRPCServerOptions::fromInitializationFile(ini.path());
        REQUIRE(options.getServerKey() == "the-key");
        REQUIRE(options.getServerCertificate()
                == loadTrimmed("self-signed-test.crt"));
    }
    SECTION("A secret file is trimmed of surrounding whitespace")
    {
        const TemporaryFile key{"\n  the-key \t\n\n", ".key"};
        const TemporaryFile certificate{"the-certificate\n", ".crt"};
        const auto ini = makeIni(
            "serverKeyFile = " + key.path().string() + "\n"
          + "serverCertificateFile = " + certificate.path().string() + "\n");
        const auto options = GRPCServerOptions::fromInitializationFile(ini.path());
        REQUIRE(options.getServerKey() == "the-key");
        REQUIRE(options.getServerCertificate() == "the-certificate");
    }
    SECTION("Only one of key and certificate throws")
    {
        const auto keyOnly = makeIni("serverKey = the-key\n");
        REQUIRE_THROWS_AS(GRPCServerOptions::fromInitializationFile(keyOnly.path()),
                          std::invalid_argument);
        const auto certificateOnly
            = makeIni("serverCertificate = the-certificate\n");
        REQUIRE_THROWS_AS(GRPCServerOptions::fromInitializationFile(certificateOnly.path()),
                          std::invalid_argument);
    }
    SECTION("Both inline and file forms of one secret throws")
    {
        const auto ini = makeIni(
            "serverKey = the-key\n"
            "serverKeyFile = " + keyPath("self-signed-test.key") + "\n"
            "serverCertificate = the-certificate\n");
        REQUIRE_THROWS_AS(GRPCServerOptions::fromInitializationFile(ini.path()),
                          std::invalid_argument);
    }
    SECTION("A missing or blank secret file throws")
    {
        const auto missing = makeIni(
            "serverKeyFile = "
          + (std::filesystem::temp_directory_path()
           / "ueat-grpcServerOptions-missing.key").string() + "\n"
          + "serverCertificate = the-certificate\n");
        REQUIRE_THROWS_AS(GRPCServerOptions::fromInitializationFile(missing.path()),
                          std::invalid_argument);

        const TemporaryFile blank{" \n\t\n", ".key"};
        const auto blankIni = makeIni(
            "serverKeyFile = " + blank.path().string() + "\n"
          + "serverCertificate = the-certificate\n");
        REQUIRE_THROWS_AS(GRPCServerOptions::fromInitializationFile(blankIni.path()),
                          std::invalid_argument);
    }
}

// boost reads "-1" into a uint16_t as 65535 without complaint, so the
// port must be parsed wider and range checked before it is narrowed.
TEST_CASE("UEventAnalysisToolBackend::GRPC::GRPCServerOptions::fromInitializationFile negative port",
          "GRPCServerOptions")
{
    const auto ini = makeIni("port = -1\n");
    REQUIRE_THROWS_AS(GRPCServerOptions::fromInitializationFile(ini.path()),
                      std::invalid_argument);
}
