#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_sign.h>
#include <sodium/utils.h>
#include <pqxx/pqxx>
#include "uEventAnalysisToolBackend/auth/database.hpp"
#include "uEventAnalysisToolBackend/auth/databaseOptions.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/database/credentials.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class Database::DatabaseImpl
{
public:
    DatabaseImpl(const DatabaseOptions &options,
                 std::shared_ptr<spdlog::logger> logger) :
        mOptions(options),
        mLogger(std::move(logger))
    {
        if (!mOptions.hasCredentials())
        {
            throw std::invalid_argument("Database credentials not set");
        }
        if (mLogger == nullptr)
        {
            // NOLINTBEGIN(misc-include-cleaner)
            auto classId
                = std::to_string (reinterpret_cast<std::uintptr_t> (this));
            mLogger = spdlog::stdout_color_mt("AuthDatabaseConsole-" + classId);
            // NOLINTEND(misc-include-cleaner)
        }
         
        connect();
        mInitialized = isConnected();
    }

    /// @brief Connect to the database
    void connect()
    {
        disconnect();
        const auto &credentials = mOptions.getCredentials();
        auto connectionString = credentials.getConnectionString();
        auto schema = credentials.getSchema();
        {
        const std::scoped_lock lock(mDatabaseMutex);
        mConnection = std::make_unique<pqxx::connection> (connectionString);
        if (mConnection)
        {
            if (!mConnection->is_open())
            {
                throw std::runtime_error(
                    "Failed to establish database connection to "
                   + credentials.getDatabaseName()
                   + " at " + credentials.getHost());
            }
            if (schema != std::nullopt)
            {
                SPDLOG_LOGGER_DEBUG(mLogger, "Updating search path to {}",
                                    *schema);
                const std::string query = "SET search_path TO "
                                        + *schema
                                        + ",public";
                {
                pqxx::work transaction(*mConnection);
                transaction.exec(query);
                transaction.commit();
                }
            }
        }
        else
        {
            throw std::runtime_error("Failed to connect to "
                                   + credentials.getDatabaseName()
                                   + " at " + credentials.getHost());
        }
        }
        SPDLOG_LOGGER_INFO(mLogger, 
                           "Connected to {} at {}",
                           credentials.getDatabaseName(),
                           credentials.getHost());
    }

    /// @brief Disconnect from the database
    void disconnect()
    {
        const std::scoped_lock lock(mDatabaseMutex);
        if (mConnection)
        {
            mConnection->close();
            mConnection = nullptr;
        }
    }

    /// @brief Am I connected to the database?
    /// @return True indicates the database is connected.
    [[nodiscard]] bool isConnected() const noexcept
    {
        const std::scoped_lock lock(mDatabaseMutex);
        if (mConnection)
        {
            return mConnection->is_open();
        }
        return false; 
    }

    /// @brief Hashes a password for storage.
    [[nodiscard]] std::string hashPassword(const std::string &password) const
    {
        std::string hashedPassword;
        hashedPassword.resize(crypto_pwhash_STRBYTES);
        // 0.7 seconds on a 2.8 GHz i7 and 256 Mb of RAM
        if (crypto_pwhash_str(hashedPassword.data(), // Output
                              password.c_str(),      // Input
                              password.length(),
                              mOperationsLimit,
                              mMemoryLimit) != 0)
        {
            throw std::runtime_error("Out of memory");
        }
        // crypto_pwhash_str wrote a NUL-terminated C string into a
        // maximum-size buffer; the encoded hash is shorter than
        // crypto_pwhash_STRBYTES so truncate at the first NUL - postgres
        // rejects TEXT with embedded NULs.
        hashedPassword.resize(std::strlen(hashedPassword.c_str()));
        return hashedPassword;
    }

    /// @brief Updates the user password.
    /// @result True on success; false if the user does not exist.
    [[nodiscard]] bool updatePassword(const std::pair<std::string, std::string> &userAndPassword)
    {
        const auto &user = userAndPassword.first;
        if (user.empty()){throw std::invalid_argument("User is empty");}
        const auto &password = userAndPassword.second;
        if (password.empty()){throw std::invalid_argument("Password is empty");}
        auto hashedPassword = hashPassword(password);
        constexpr std::string_view query{"SELECT auth.update_user_password($1, $2)"};
        const pqxx::params parameters{user, hashedPassword};
        bool success{false};
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        success = row.at(0).as<bool> ();
        transaction.commit();
        }
        return success;
    }

    /// @brief Adds a user.
    /// @result True on success; false if the user already exists.
    [[nodiscard]] bool addUser(const std::pair<std::string, std::string> &userAndPassword)
    {
        const auto &user = userAndPassword.first;
        if (user.empty()){throw std::invalid_argument("User is empty");}
        const auto &password = userAndPassword.second;
        if (password.empty()){throw std::invalid_argument("Password is empty");}
        auto hashedPassword = hashPassword(password);
        constexpr std::string_view query{"SELECT auth.add_user($1, $2)"};
        const pqxx::params parameters{user, hashedPassword};
        bool success{false};
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        success = row.at(0).as<bool> ();
        transaction.commit();
        }
        return success;
    }

    /// @brief Removes a user.
    /// @result True if the user was removed; false if no such user.
    [[nodiscard]] bool removeUser(const std::string &user)
    {
        if (user.empty()){throw std::invalid_argument("User is empty");}
        constexpr std::string_view query{"SELECT auth.remove_user($1)"};
        const pqxx::params parameters{user};
        bool success{false};
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        success = row.at(0).as<bool> ();
        transaction.commit();
        }
        return success;
    }

    /// @brief Gets the (schema, permission) pairs for the user.
    [[nodiscard]] std::vector<std::pair<std::string, std::string>>
        getPermissions(const std::string &user) const
    {
        if (user.empty()){throw std::invalid_argument("User is empty");}
        constexpr std::string_view query{
            "SELECT schema_name, permission_name FROM auth.list_user_schemas($1)"};
        const pqxx::params parameters{user};
        std::vector<std::pair<std::string, std::string>> result;
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        for (const auto &row : transaction.exec(query, parameters))
        {
            result.emplace_back(row.at(0).as<std::string> (),
                                row.at(1).as<std::string> ());
        }
        }
        return result;
    }

    /// @brief Gets the hashed password from the database.
    /// @result The hashed password (or null if the user does not exist).
    [[nodiscard]] std::optional<std::string> 
        getHashedPasswordFromDatabase(const std::string &user) const
    {
        std::optional<std::string> hashedPassword; 
        if (user.empty())
        {
            throw std::runtime_error("User is empty");
        } 
        constexpr std::string_view query{"SELECT auth.get_password_hash($1)"};
        const pqxx::params parameters{user};
        // Null indicates no user
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        if (!row.at(0).is_null())
        {
            hashedPassword = std::make_optional<std::string> (row[0].as<std::string> ());
        }
        }
        return hashedPassword;
    }

    /// @brief Record a successful login.
    [[nodiscard]] bool recordLogin(const std::string &user)
    {
        bool success{false};
        constexpr std::string_view query{"SELECT auth.record_login($1)"};
        const pqxx::params parameters{user};
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        success = row.at(0).as<bool> ();
        // Without the commit the last_login update rolls back on the
        // transaction's destruction.
        transaction.commit();
        }
        return success;
    }

    /// @brief Decodes base64 text into exactly expectedLength bytes.
    /// @result The bytes, or null if the text is not valid base64 or is
    ///         the wrong size.
    [[nodiscard]] static std::optional<std::vector<unsigned char>>
        base64Decode(const std::string &text, const size_t expectedLength)
    {
        std::vector<unsigned char> result(expectedLength);
        size_t actualLength{0};
        if (sodium_base642bin(result.data(), result.size(),
                              text.data(), text.size(),
                              nullptr, &actualLength, nullptr,
                              sodium_base64_VARIANT_ORIGINAL) != 0)
        {
            return std::nullopt;
        }
        if (actualLength != expectedLength){return std::nullopt;}
        return result;
    }

    /// @brief Registers a public key for the user.
    /// @result True on success; false if the user does not exist or the
    ///         key (name) is already registered.
    [[nodiscard]] bool addUserKey(const std::string &user,
                                  const std::string &keyName,
                                  const std::string &publicKey)
    {
        if (user.empty()){throw std::invalid_argument("User is empty");}
        if (keyName.empty()){throw std::invalid_argument("Key name is empty");}
        if (publicKey.empty())
        {
            throw std::invalid_argument("Public key is empty");
        }
        // Fail fast on junk before it lands in the database.
        if (!base64Decode(publicKey, crypto_sign_PUBLICKEYBYTES))
        {
            throw std::invalid_argument(
                "Public key is not a base64 ed25519 public key");
        }
        constexpr std::string_view query{"SELECT auth.add_user_key($1, $2, $3)"};
        const pqxx::params parameters{user, keyName, publicKey};
        bool success{false};
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        success = row.at(0).as<bool> ();
        transaction.commit();
        }
        return success;
    }

    /// @brief Revokes the user's named key.
    /// @result True if an active key was revoked.
    [[nodiscard]] bool revokeUserKey(const std::string &user,
                                     const std::string &keyName)
    {
        if (user.empty()){throw std::invalid_argument("User is empty");}
        if (keyName.empty()){throw std::invalid_argument("Key name is empty");}
        constexpr std::string_view query{"SELECT auth.revoke_user_key($1, $2)"};
        const pqxx::params parameters{user, keyName};
        bool success{false};
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        success = row.at(0).as<bool> ();
        transaction.commit();
        }
        return success;
    }

    // Get user by their (public) key.  Only active (unrevoked, unexpired)
    // keys resolve to a user.
    [[nodiscard]] std::optional<std::string> getUserByKey(const std::string &publicKey) const
    {
        std::optional<std::string> result{std::nullopt};
        if (publicKey.empty())
        {
            throw std::invalid_argument("Public key is empty");
        }
        constexpr std::string_view query{"SELECT auth.get_user_by_key($1)"};
        const pqxx::params parameters{publicKey};
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        if (!row.at(0).is_null())
        {
            result = std::optional<std::string> (row[0].as<std::string> ());
        }
        }
        return result;
    }

    /// @brief Records a successful key authentication; also touches the
    ///        user's last_login.
    [[nodiscard]] bool recordKeyUse(const std::string &publicKey)
    {
        bool success{false};
        constexpr std::string_view query{"SELECT auth.record_key_use($1)"};
        const pqxx::params parameters{publicKey};
        {
        const std::scoped_lock lock(mDatabaseMutex);
        pqxx::work transaction(*mConnection);
        auto row = transaction.exec(query, parameters).one_row();
        success = row.at(0).as<bool> ();
        transaction.commit();
        }
        return success;
    }

    // Auth user by public key:
    // The user sends a message, a 64 byte detached signature of that
    // message, and their 32 byte public key (the latter two base64).
    // NOLINTBEGIN(bugprone-easily-swappable-parameters)
    [[nodiscard]] IAuthenticator::Result authenticateByKey(
        const std::string &message,
        const std::string &signature,
        const std::string &publicKey)
    // NOLINTEND(bugprone-easily-swappable-parameters)
    {
        // Is this an active key we know?
        auto user = getUserByKey(publicKey);
        if (!user)
        {
            SPDLOG_LOGGER_WARN(mLogger,
                               "User not found for provided public key");
            return IAuthenticator::Result::InvalidCredentials;
        }
        // Unpack the key and signature
        auto publicKeyBytes
            = base64Decode(publicKey, crypto_sign_PUBLICKEYBYTES);
        auto signatureBytes = base64Decode(signature, crypto_sign_BYTES);
        if (!publicKeyBytes || !signatureBytes)
        {
            SPDLOG_LOGGER_WARN(mLogger,
                               "Malformed signature or public key for {}",
                               *user);
            return IAuthenticator::Result::InvalidCredentials;
        }
        // Did the holder of the private key sign this message?
        if (crypto_sign_verify_detached(
                signatureBytes->data(),
                reinterpret_cast<const unsigned char *> (message.data()),
                message.size(),
                publicKeyBytes->data()) != 0)
        {
            SPDLOG_LOGGER_WARN(mLogger,
                               "Signature verification failed for {}",
                               *user);
            return IAuthenticator::Result::InvalidCredentials;
        }
        if (!recordKeyUse(publicKey))
        {
            SPDLOG_LOGGER_WARN(mLogger, "Failed to record key use for {}",
                               *user);
        }
        SPDLOG_LOGGER_INFO(mLogger, "Verified {} by key", *user);
        return IAuthenticator::Result::Authenticated;
    }
       

    // Let's check this user's password
    [[nodiscard]] IAuthenticator::Result authenticateByPassword(
        const std::pair<std::string, std::string> &userAndPassword)
    {
        auto user = userAndPassword.first;
        auto password = userAndPassword.second;
        auto hashedPassword = getHashedPasswordFromDatabase(user);
        if (hashedPassword != std::nullopt)
        {
            if (crypto_pwhash_str_verify(hashedPassword->c_str(),
                                         password.c_str(),
                                         password.length()) == 0)
            {
                // Okay, we're in update
                if (!recordLogin(user))
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                                       "Failed to record login for {}",
                                       user); 
                }
                // In case I changed some parameters see if we need a rehash
                if (crypto_pwhash_str_needs_rehash(
                       hashedPassword->c_str(),
                       crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE))
                {
                    // Stored hash uses old/different params. 
                    // We'll update that now.
                    SPDLOG_LOGGER_INFO(mLogger, "Reshashing password for {}",
                                       user);
                    try
                    {
                        if (!updatePassword(std::pair{user, password}))
                        {
                            SPDLOG_LOGGER_WARN(mLogger,
                                               "Password rehash did not update {}",
                                               user);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        // It's actually okay - we'll just try again on next
                        // login.  But the user is good to go
                        SPDLOG_LOGGER_WARN(mLogger,
                                           "Password update failed because {}",
                                           std::string {e.what()});
                    }
                }
                return IAuthenticator::Result::Authenticated;
            }
            else
            {
                // Wrong password
                SPDLOG_LOGGER_WARN(mLogger,
                                   "{} provided incorrect password",
                                   user);
                return IAuthenticator::Result::InvalidCredentials; 
            }
        }
        else
        {
            SPDLOG_LOGGER_WARN(mLogger, "{} not in database", user);
            return IAuthenticator::Result::InvalidCredentials;
        }
        SPDLOG_LOGGER_ERROR(mLogger, "Unhandled login workflow");
        return IAuthenticator::Result::ServerError;
    }
    DatabaseOptions mOptions;
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    mutable std::mutex mDatabaseMutex;
    std::unique_ptr<pqxx::connection> mConnection{nullptr};
    int mOperationsLimit{crypto_pwhash_OPSLIMIT_MODERATE}; 
    int mMemoryLimit{crypto_pwhash_MEMLIMIT_MODERATE};
    bool mInitialized{false};
};

/// Constructor
Database::Database(const DatabaseOptions &options,
                   std::shared_ptr<spdlog::logger> logger) :
    pImpl(std::make_unique<DatabaseImpl> (options, std::move(logger)))
{
}

/// Auth the user
IAuthenticator::Result Database::authenticateBasic(
    const std::pair<std::string, std::string> &userNameAndPassword)
{
    if (userNameAndPassword.first.empty())
    {
        throw std::invalid_argument("User is empty");
    }
    // A database problem is our problem, not the client's - so this is a
    // server error rather than an escaped exception.
    try
    {
        return pImpl->authenticateByPassword(userNameAndPassword);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Basic authentication failed because {}",
                            std::string {e.what()});
        return IAuthenticator::Result::ServerError;
    }
}

/// Permissions
std::vector<std::pair<std::string, std::string>>
Database::getPermissions(const std::string &user) const
{
    return pImpl->getPermissions(user);
}

/// Add a user
bool Database::addUser(
    const std::pair<std::string, std::string> &userNameAndPassword)
{
    return pImpl->addUser(userNameAndPassword);
}

/// Update a password
bool Database::updatePassword(
    const std::pair<std::string, std::string> &userNameAndPassword)
{
    return pImpl->updatePassword(userNameAndPassword);
}

/// Remove a user
bool Database::removeUser(const std::string &user)
{
    return pImpl->removeUser(user);
}

/// Register a key
bool Database::addUserKey(const std::string &user,
                          const std::string &keyName,
                          const std::string &publicKey)
{
    return pImpl->addUserKey(user, keyName, publicKey);
}

/// Revoke a key
bool Database::revokeUserKey(const std::string &user,
                             const std::string &keyName)
{
    return pImpl->revokeUserKey(user, keyName);
}

/// Auth by key
IAuthenticator::Result Database::authenticateKey(
    const std::string &message,
    const std::string &signature,
    const std::string &publicKey)
{
    if (message.empty()){throw std::invalid_argument("Message is empty");}
    if (signature.empty()){throw std::invalid_argument("Signature is empty");}
    if (publicKey.empty())
    {
        throw std::invalid_argument("Public key is empty");
    }
    // As with basic authentication a database problem is our problem.
    try
    {
        return pImpl->authenticateByKey(message, signature, publicKey);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Key authentication failed because {}",
                            std::string {e.what()});
        return IAuthenticator::Result::ServerError;
    }
}

/// Destructor
Database::~Database() = default;
