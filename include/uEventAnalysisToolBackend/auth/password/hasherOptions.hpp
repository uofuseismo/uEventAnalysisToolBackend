#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_PASSWORD_HASHER_OPTIONS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_PASSWORD_HASHER_OPTIONS_HPP
#include <cstddef>
#include <filesystem>
#include <memory>

namespace UEventAnalysisToolBackend::Auth::Password
{

/// @class HasherOptions hasherOptions.hpp
/// @brief Defines the internal password hashing policy.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class HasherOptions
{
public:
    enum class OperationsLimit
    {
        Interactive, /*!< This is the fastest and least secure.
                          It's a good choice if people frequently
                          use basic auth.  This requires 2 passes
                          and about 64 MiB of RAM. */
        Moderate,    /*!< A compromise between interactive and sensitive.
                          This requires 3 passes and 256 MiB of RAM. */
        Sensitive    /*!< High-security and high-computation.  This
                          requires 4 passes and 1 GiB of RAM. */
    };
public:
    /// @brief Constructor.
    HasherOptions();
    /// @brief Copy constructor.
    HasherOptions(const HasherOptions &options);
    /// @brief Move constructor.
    HasherOptions(HasherOptions &&options) noexcept;

    /// @brief The Argon2 operations limit.
    /// @param[in] limit  The operations limit.
    void setOperationsLimit(OperationsLimit limit) noexcept;
    /// @result The operations limit.
    /// @note By default this is interactive.
    [[nodiscard]] OperationsLimit getOperationsLimit() const noexcept;
 
    /// @brief The Argon2 memory limit in bytes.
    /// @throws std::invalid_argument if this is not at least 8192 bytes.
    void setMemoryLimitInBytes(size_t memoryLimit);
    /// @result The Argon2 memory limit in bytes. 
    /// @note By default this is 64 MiB.
    [[nodiscard]] size_t getMemoryLimitInBytes() const noexcept;

    /// @brief Creates the hashing policy from an initialization file.
    /// @throws std::invalid_argument if the ini file path does not exist.
    [[nodiscard]] static HasherOptions fromInitializationFile(const std::filesystem::path &path, const std::string &section = "PasswordHasherOptions");

    /// @brief Destructor.
    ~HasherOptions();
    /// @brief Copy assignment.
    HasherOptions& operator=(const HasherOptions &options);
    /// @brief Move assignment.
    HasherOptions& operator=(HasherOptions &&options) noexcept;
private:
    class HasherOptionsImpl;
    std::unique_ptr<HasherOptionsImpl> pImpl;
};

}
#endif
