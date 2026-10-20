#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_PASSWORD_HASHER_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_PASSWORD_HASHER_HPP
#include <expected>
#include <memory>
#include <string>

namespace UEventAnalysisToolBackend::Auth::Password
{
 class HasherOptions;
}

namespace UEventAnalysisToolBackend::Auth::Password
{
/// @class Hasher hasher.hpp
/// @brief A password hasher.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class Hasher
{
public:
    enum class ParseError
    {
    };
public:
    /// @brief Constructor.
    explicit Hasher(const HasherOptions &options);
    /// @brief Copy constructor.
    Hasher(const Hasher &hasher);
    /// @brief Move constructor.
    Hasher(Hasher &&hasher) noexcept;

    /// @brief Destructor.
    ~Hasher();

    /// @brief Hashes a password for storage.
    /// @param[in] password  The plain-text password.
    /// @result The encoded, Argon2 hashed password.
    /// @note The hashed password result is safe for a TEXT column.
    /// @throws std::runtime_error if there is not enough memory to hash.
    [[nodiscard]] std::string hash(const std::string &password) const;

    /// @brief Asks whether a stored hash was made at a different cost.
    /// @param[in] encodedHash  The hashed password as it came out of the
    ///                         database.
    /// @result True indicates that rehashing the password at the 
    ///         cost defined by the options would change it.
    ///         Otherwise, there is no value to re-hashing the password.
    /// @note If this returns true then the next thing to do is call
    ///       \c hash().
    /// @throws std::runtime_error if the password could not be hashed. 
    ///         This likely means the database result is unreadable and
    ///         should be rehashed.
    [[nodiscard]] bool needsRehash(const std::string &encodedHash) const;

    /// @brief Copy assignment.
    Hasher& operator=(const Hasher &hasher);
    /// @brief Move assignment.
    Hasher& operator=(Hasher &&hasher) noexcept;

    Hasher() = delete;
private:
    class HasherImpl;
    std::unique_ptr<HasherImpl> pImpl;
};
}
#endif
