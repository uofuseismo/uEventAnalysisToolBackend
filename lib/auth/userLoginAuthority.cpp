#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <boost/json/object.hpp>
#include <sodium/crypto_sign.h>
#include <sodium/utils.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolBackend/auth/userList.hpp"
#include "databaseUtilities.hpp"

using namespace UEventAnalysisToolBackend::Auth;

namespace
{

/// Bounds the work done on client input before anything is verified.
constexpr size_t MAX_ASSERTION_BYTES{4096};
/// An assertion is good for at most this long after it was signed.
constexpr std::chrono::seconds MAX_ASSERTION_LIFETIME{60};
/// Tolerated client clock drift for iat.
constexpr std::chrono::seconds CLOCK_SKEW{10};
/// The jti goes into the database, so cap it.
constexpr size_t MAX_JTI_BYTES{128};

/// What the rest of the login needs from a verified assertion.
struct Assertion
{
    std::string subject;   // lower-cased
    std::string jti;
    std::chrono::system_clock::time_point expiresAt;
};

/// Check the assertion is signed by this public.
/// @param[in] publicKey  The raw 32-byte Ed25519 public key.
/// @param[in] assertion  The compact JWS: header.payload.signature.
[[nodiscard]] bool verifyAssertionSignature(
    const std::vector<unsigned char> &publicKey,
    std::string_view assertion)
{
    if (publicKey.size() != crypto_sign_PUBLICKEYBYTES){return false;}
    if (assertion.empty() || assertion.size() > MAX_ASSERTION_BYTES)
    {
        return false;
    }
    // header.payload.signature - exactly two dots, nothing empty.
    const auto firstDot = assertion.find('.');
    const auto lastDot = assertion.rfind('.');
    if (firstDot == std::string_view::npos ||
        firstDot == 0 ||
        firstDot == lastDot ||
        lastDot == assertion.size() - 1)
    {
        return false;
    }
    // What EdDSA JWS signs (RFC 8037): the ASCII of "header.payload".
    const auto signingInput = assertion.substr(0, lastDot);
    const auto encodedSignature = assertion.substr(lastDot + 1);


    std::array<unsigned char, crypto_sign_BYTES> signature{};
    size_t signatureLength{0};
    // Fails if the text isn't base64url or decodes to more than 64 bytes.
    if (sodium_base642bin(signature.data(), signature.size(),
                          encodedSignature.data(), encodedSignature.size(),
                          nullptr, &signatureLength, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
    {
        return false;
    }
    if (signatureLength != crypto_sign_BYTES){return false;}

    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    return crypto_sign_verify_detached(
               signature.data(),
               reinterpret_cast<const unsigned char *> (signingInput.data()),
               signingInput.size(),
               publicKey.data()) == 0;
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
}

/// Does the (already signature-verified) assertion say the right
/// things?  Nothing here is trusted until \c verifyAssertionSignature()
/// returns true.
/// @param[in] assertion  The compact JWS.
/// @param[in] audience   This server's issuer string; the assertion must
///                       name it, so one minted for another service
///                       can't be replayed here.
/// @param[in] now        The current time.
/// @result The claims the login needs, or nothing if any check fails.
[[nodiscard]] std::optional<Assertion>
    parseAssertion(const std::string &assertion,
                   const std::chrono::system_clock::time_point now,
                   const std::string &audience)
{
    try
    {
        const auto decoded
            = jwt::decode<jwt::traits::boost_json> (assertion);
        // Never let the header pick the algorithm - step 1 already used
        // Ed25519.  This only rejects a client that claims otherwise.
        if (decoded.get_algorithm() != "EdDSA"){return std::nullopt;}
        if (!decoded.has_subject() ||
            !decoded.has_audience() ||
            !decoded.has_issued_at() ||
            !decoded.has_expires_at() ||
            !decoded.has_id())
        {
            return std::nullopt;
        }

        if (!decoded.get_audience().contains(audience)){return std::nullopt;}

        const auto issuedAt = decoded.get_issued_at();
        const auto expiresAt = decoded.get_expires_at();
        // Expired
        if (expiresAt <= now){return std::nullopt;}
        // Future
        if (issuedAt > now + CLOCK_SKEW){return std::nullopt;}
        // Too long
        if (expiresAt - issuedAt > MAX_ASSERTION_LIFETIME){return std::nullopt;}

        auto jti = decoded.get_id();
        if (jti.empty() || jti.size() > MAX_JTI_BYTES){return std::nullopt;}

        auto subject = decoded.get_subject();
        if (subject.empty()){return std::nullopt;}
        std::ranges::transform(subject, subject.begin(),
                               [](unsigned char c)
                               {
                                   return static_cast<char> (std::tolower(c));
                               });

        return Assertion{std::move(subject), std::move(jti), expiresAt};
    }
    catch (const std::exception &)
    {
        // Malformed client input, not a server error.
        return std::nullopt;
    }
}

/// The canonical text form of a public key, as auth.user_keys stores it.
[[nodiscard]] std::string encodeBase64(const std::vector<unsigned char> &bytes)
{
    // The encoded length includes the trailing NUL that libsodium writes.
    std::string encoded(sodium_base64_ENCODED_LEN(bytes.size(),
                                                  sodium_base64_VARIANT_ORIGINAL),
                        '\0');
    sodium_bin2base64(encoded.data(), encoded.size(),
                      bytes.data(), bytes.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    encoded.pop_back();   // drop the NUL
    return encoded;
}

}

class UserLoginAuthority::UserLoginAuthorityImpl :
    public Detail::DatabaseConnection::Database
{
public:
    UserLoginAuthorityImpl(
        const UserLoginAuthorityOptions &options,
        std::shared_ptr<spdlog::logger> logger) :
        Detail::DatabaseConnection::Database
        {
            "UserLoginAuthorityConsole",
            options.getDatabaseCredentials(),
            std::move(logger)
        },
        mOptions(options)
    {
        if (!mOptions.hasKeyPairAndAlgorithm())
        {
            throw std::invalid_argument("Key pair and algorithm not set");
        }
        if (!mOptions.hasIssuer())
        {
            throw std::invalid_argument("Issuer not set");
        }
        if (!mOptions.hasTimeToLive())
        {
            throw std::invalid_argument("Time-to-live not set");
        }
        mPasswordHasher
            = std::make_unique<Password::Hasher>
              (mOptions.getPasswordHasherOptions());
        // Connect since this will get hit fairly often
        try
        {
            connect();
            if (!isConnected())
            {
                throw std::runtime_error("Failed to connect to user database");
            }
            SPDLOG_LOGGER_INFO(mLogger, "Connected to user auth database");
        }
        catch (const std::exception &e) 
        {
            throw std::runtime_error(
                std::string {"Failed to connect to user database because "}
              + e.what());
        }
        mInitialized = true;
    }

    /// @brief Gets the user name from the database.  This enforces
    ///        consistency in casing.
    [[nodiscard]] std::optional<std::string>
        getUserName(const std::string &user)
    {
        constexpr std::string_view query{"SELECT auth.get_user_name($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction)
             -> std::optional<std::string>
            {
                auto row = transaction.exec(query, parameters).one_row();
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<std::string> ();
            });
    }

    /// @brief Creates the token; permissions, when present, ride in the
    ///        signed payload.
    [[nodiscard]] std::string createToken(const std::string &user)
    {   
        auto isAdmin = isAdministrator(user);
        auto permissions = getPermissions(user);
        auto name = getUserName(user);
        if (name == std::nullopt)
        {
            throw std::runtime_error(user + " does not exist");
        }
        const std::chrono::seconds expiration{mOptions.getTimeToLive()};
        auto token = jwt::create<jwt::traits::boost_json> (); 
        token.set_subject(*name)
             .set_issuer(mOptions.getIssuer())
             .set_type("JWT")
             .set_issued_now()
             .set_expires_in(expiration);
        token.set_payload_claim("administrator", isAdmin); 
        token.set_payload_claim("scope", "user");
        if (!permissions.empty())
        {
            boost::json::object permissionsObject;
            for (const auto &[schema, permission] : permissions)
            {
                permissionsObject[schema] = permission;
            }
            const std::string permissionsClaim{"permissions"};
            token.set_payload_claim(
                permissionsClaim,
                jwt::basic_claim<jwt::traits::boost_json>
                    {boost::json::value {permissionsObject}});
        }
        if (mOptions.getAlgorithm() ==
            UserLoginAuthorityOptions::Algorithm::EdDSA25519)
        {
            const std::string publicKeyPassword{""};
            const std::string privateKeyPassword{""};
            auto [publicKey, privateKey] = mOptions.getKeyPair();
            return token.sign(jwt::algorithm::ed25519(
                                  publicKey,
                                  privateKey,
                                  publicKeyPassword,
                                  privateKeyPassword));
        }
        else
        {
            throw std::runtime_error("Only eddsa25519 implemented");
        }
    }

    /// @brief Gets the (schema, permission) pairs for the user.
    [[nodiscard]] std::vector<std::pair<std::string, std::string>>
        getPermissions(const std::string &user)
    {   
        if (user.empty()){throw std::invalid_argument("User is empty");}
        constexpr std::string_view query{
            "SELECT schema_name, permission_name FROM auth.list_user_schemas($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction)
                -> std::vector<std::pair<std::string, std::string>>
            {
                std::vector<std::pair<std::string, std::string>> result;
                for (const auto &row : transaction.exec(query, parameters))
                {
                    result.emplace_back(row.at(0).as<std::string> (), 
                                        row.at(1).as<std::string> ());
                }
                return result;
            });
    }

    /// @result True if this is the first time the (key, jti) has been seen.
    ///         False is a replay (or an inactive key).
    [[nodiscard]] 
    bool consumeAssertion(const std::string &key,
                          const std::string &jti,
                          const std::chrono::system_clock::time_point expiresAt)
    {
        constexpr std::string_view query
        {
            "SELECT auth.consume_assertion($1, $2, to_timestamp($3))"
        };
        const auto expiresAtSeconds
            = std::chrono::duration_cast<std::chrono::seconds>
              (expiresAt.time_since_epoch()).count();
        const pqxx::params parameters{key, jti, expiresAtSeconds};
        return withTransaction<pqxx::work>(
            [&](pqxx::work &transaction) -> bool
            {
                auto row = transaction.exec(query, parameters).one_row();
                const auto consumed = row.at(0).as<bool> ();
                // Without the commit the jti isn't burned and the replay
                // check is void.
                transaction.commit();
                return consumed;
            });
     }

    /// @brief Verify this user is an admin.
    [[nodiscard]] bool isAdministrator(const std::string &user)
    {   
        constexpr std::string_view query{"SELECT auth.user_is_admin($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction) -> bool
            {   
                auto row = transaction.exec(query, parameters).one_row();
                const auto isAdmin = row.at(0).as<bool> (); 
                return isAdmin;
            }); 
    }

    /// @brief Updates the password. 
    /// @note If this the user's first login this will also clear
    ///       provisional_until and stamp activated.
    /// @result True indicates the user's password was updated.
    ///         False indicates either - the user doesn't exist or
    ///         user is provisional and the issued password has expired.
    [[nodiscard]] 
    bool changePassword(
        const std::pair<std::string, std::string> &userAndHashedPassword)
    {
        constexpr std::string_view query{"SELECT auth.update_user_password($1, $2)"};
        const pqxx::params parameters{userAndHashedPassword.first,
                                      userAndHashedPassword.second};
        return withTransaction<pqxx::work>(
            [&](pqxx::work &transaction) -> bool
            {
                const auto success
                   = transaction.exec(query, parameters).one_row()
                                                        .at(0).as<bool> ();
                transaction.commit();
                return success;
            });
    }

    /// @brief Record a successful login.
    [[nodiscard]] bool recordLogin(const std::string &user)
    {
        constexpr std::string_view query{"SELECT auth.record_login($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::work>(
            [&](pqxx::work &transaction) -> bool
            {
                auto row = transaction.exec(query, parameters).one_row();
                const auto success = row.at(0).as<bool> ();
                // Without the commit the last_login update rolls back on
                // the transaction's destruction.
                transaction.commit();
                return success;
            });
    }

    /// @brief Records key use.
    [[nodiscard]] bool recordKeyUse(const std::string &key)
    {
        constexpr std::string_view query{"SELECT auth.record_key_use($1)"};
        const pqxx::params parameters{key};
        return withTransaction<pqxx::work>(
            [&](pqxx::work &transaction) -> bool
            {
                auto row = transaction.exec(query, parameters).one_row();
                const auto success = row.at(0).as<bool> ();
                // Without the commit the last_login update rolls back on
                // the transaction's destruction.
                transaction.commit();
                return success;
            });
    } 

    /// @brief Gets the hashed password from the database.
    /// @result The hashed password (or null if the user does not exist).
    [[nodiscard]] std::optional<std::string> 
        getHashedPasswordFromDatabase(const std::string &user)
    {
        if (user.empty())
        {
            throw std::runtime_error("User is empty");
        }
        constexpr std::string_view query{"SELECT auth.get_password_hash($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction) -> std::optional<std::string>
            {
                auto row = transaction.exec(query, parameters).one_row();
                // Null indicates no user
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<std::string> ();
            });
    }

    /// @brief Indicates the user must (first) change their password.
    /// @result True means the user must first change their password before
    ///         logging in.
    [[nodiscard]] std::optional<bool> userMustChangePassword(const std::string &user)
    {
        if (user.empty())
        {
            throw std::runtime_error("User is empty");
        }
        constexpr std::string_view query{"SELECT auth.user_must_change_password($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction) -> std::optional<bool>
            {
                auto row = transaction.exec(query, parameters).one_row();
                // Null indicates no user
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<bool> ();
            });
    }

    // @result True indicates success.  False indicates the user is unknown.
    [[nodiscard]] bool addUserKey(const std::string &user,
                                  const std::string &keyName,
                                  const std::string &publicKey,
                                  const std::chrono::seconds &expiresAfter)
    {
          
        constexpr std::string_view query{
           "SELECT auth.add_user_key($1, $2, $3, $4, NOW() + make_interval(secs => $5), $6)"};
        const pqxx::params parameters{user, keyName, publicKey,
                                      "ed25519",
                                      expiresAfter.count(),
                                      mOptions.getMaximumNumberOfLoginKeys()};
        return withTransaction<pqxx::work>(
            [&](pqxx::work &transaction) -> bool
            {
                auto row = transaction.exec(query, parameters).one_row();
                const auto added = row.at(0).as<bool> ();
                transaction.commit();
                return added;
            });                   


    }

    // @result The key owner (user) name if the key is active (i.e., exists and
    //         is not revoked or expired etc.) 
    [[nodiscard]] std::optional<std::string> getUserByKey(const std::string &key)
    {
        if (key.empty())
        {   
            throw std::runtime_error("Key is empty");
        }
        constexpr std::string_view query{"SELECT auth.get_user_by_key($1)"};
        const pqxx::params parameters{key};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction)->std::optional<std::string>
            {
                auto row = transaction.exec(query, parameters).one_row();
                // Null indicates no user
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<std::string> (); 
            });
    }

    // Check the user's password
    [[nodiscard]] IAuthenticator::Result authenticateByUserNameAndPassword(
        const std::pair<std::string, std::string> &userAndPassword)
    {   
        auto user = userAndPassword.first;
        auto password = userAndPassword.second;
        auto hashedPassword = getHashedPasswordFromDatabase(user);
        if (hashedPassword != std::nullopt)
        {
            if (Password::Hasher::verify(password, *hashedPassword))
            {
                auto mustChangePassword = userMustChangePassword(user);
                if (mustChangePassword.has_value() && *mustChangePassword)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                                       "Rejecting {} - password not yet changed",
                                       user);
                    return IAuthenticator::Result::PasswordChangeRequired;
                }
                // Rehash required?
                try
                {
                    if (mPasswordHasher->needsRehash(*hashedPassword))
                    {
                        SPDLOG_LOGGER_INFO(mLogger,
                                           "Rehashing password for {}", user);
                        auto newPassword = mPasswordHasher->hash(password);
                        if (!changePassword(std::pair{user, newPassword}))
                        {
                            // Should not happen but want this to be really
                            // annoying for me instead of locking them out for
                            // specifying the right credentials - hence no return
                            // servererrorr
                            SPDLOG_LOGGER_ERROR(mLogger,
                               "Failed to change password for {}; proceeding",
                               user);
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    SPDLOG_LOGGER_ERROR(mLogger,
                    "Failed to rehash password for {} because {}; proceeding",
                    user, e.what());
                } 

                try
                {
                    if (!recordLogin(user))
                    {
                        SPDLOG_LOGGER_WARN(mLogger,
                                           "Failed to record login for {}",
                                           user); 
                    }
                }
                catch (const std::exception &e)
                {
                    SPDLOG_LOGGER_ERROR(mLogger,
                    "Failed to to record login for {} because {}; proceeding",
                    user, e.what());
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

//private:
    UserLoginAuthorityOptions mOptions;
    std::unique_ptr<Password::Hasher> mPasswordHasher{nullptr};
    bool mInitialized{false};
};

/// Constructor
UserLoginAuthority::UserLoginAuthority
(
    const UserLoginAuthorityOptions &options,
    std::shared_ptr<spdlog::logger> logger
) :
    pImpl(std::make_unique<UserLoginAuthorityImpl> (options,
                                                    std::move(logger)))
{
}
    
/// Initialized
bool UserLoginAuthority::isInitialized() const noexcept
{
    return pImpl->mInitialized;
}

/// Get the password policy
Password::PasswordPolicy UserLoginAuthority::getPasswordPolicy() const
{
    if (!isInitialized()) 
    {
        throw std::runtime_error("Class not initialized");
    }
    return pImpl->mOptions.getPasswordPolicy();
}

/// Login with password and get a token
std::expected<std::string, IAuthenticator::Result>
UserLoginAuthority::loginWithPassword(
    const std::pair<std::string, std::string> &userNameAndPassword) const
{
    if (!isInitialized())
    {   
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(IAuthenticator::Result::ServerError);
    }   
    auto user = userNameAndPassword.first;
    std::ranges::transform(user, user.begin(),
                       [](const unsigned char c)
                       {
                           return static_cast<char> (std::tolower(c));
                       });
    if (user.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                         "Rejecting user login attempt because user is empty");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
    // Check against database
    try 
    {   
        auto result
            = pImpl->authenticateByUserNameAndPassword(
                 std::pair{ user, userNameAndPassword.second} );
        if (result == IAuthenticator::Result::Authenticated)
        {
            // Create the JWT
            try
            {
                return pImpl->createToken(user); 
            }
            catch (const std::exception &e) 
            {
                SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                    "Failed to create token for {} because {}",
                                    user, e.what());
                return std::unexpected(IAuthenticator::Result::ServerError);
            }
        }
        return std::unexpected(result);
    }   
    catch (const std::exception &e) 
    {   
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Database failure {} when authentcating {}",
                           e.what(), user);
        return std::unexpected(IAuthenticator::Result::ServerError);
    }   
}

/// Login with a key
std::expected<std::string, IAuthenticator::Result>
UserLoginAuthority::loginWithKey(
    const std::vector<unsigned char> &publicKey,
    const std::string &assertion) const
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(IAuthenticator::Result::ServerError);
    }
    // Step 1: Verify signature before touching database
    if (!::verifyAssertionSignature(publicKey, assertion))
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Rejecting key login; bad signature");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
    // Check the claims - alg(orithm) is eddsa, aud(ience) is issuer, and now
    // the time is within in a minute to ensure this is short-lived
    const auto claims
        = ::parseAssertion(assertion,
                           std::chrono::system_clock::now(),
                           pImpl->mOptions.getIssuer());
    if (!claims)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Rejecting key login; bad or expired assertion");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
    auto encodedKey = ::encodeBase64(publicKey);
    // Check the user actually installed this key
    std::string user;
    try
    {
        auto userResult = pImpl->getUserByKey(encodedKey);
        if (!userResult.has_value())
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
               "No corresponding key found for user login attempt");
            return std::unexpected(IAuthenticator::Result::InvalidCredentials);
        } 
        user = std::move(*userResult);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Error getting user by key - {}", e.what());
        return std::unexpected(IAuthenticator::Result::ServerError);
    }
    // Check the subject is the owner's key
    if (user != claims->subject)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
           "Rejecting key login; assertion subject {} is not key owner {}",
           claims->subject, user);
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }

    // Burn the key so it doesn't get used again - false indicates a replay
    try
    {
        if (!pImpl->consumeAssertion(encodedKey, claims->jti,
                                     claims->expiresAt))
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
                               "Rejecting key login for {}; assertion replayed",
                               user);
            return std::unexpected(IAuthenticator::Result::InvalidCredentials);
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to consume assertion for {} because {}",
                            user,
                            e.what());
        return std::unexpected(IAuthenticator::Result::ServerError);
    }

    // Mint the JWT
    std::string token;
    try          
    {
        token = pImpl->createToken(user);
    }
    catch (const std::exception &e) 
    { 
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to create token for {} because {}",
                            user, e.what());
        return std::unexpected(IAuthenticator::Result::ServerError);
    }
    try
    {
        if (!pImpl->recordKeyUse(encodedKey))
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
                               "Failed to record key use for {}",
                               user);
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Failed to record key use for {} because {}",
                           user, e.what());
    }
    return token;
}

/// Change the user name and password
std::expected<void, UserLoginAuthority::ChangePasswordError>
UserLoginAuthority::changePassword(
    const std::pair<std::string, std::string> &userNameAndPassword,
    const std::string &newPassword)
{
    if (!isInitialized())
    {       
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(
           UserLoginAuthority::ChangePasswordError::ServerError);
    }   
    // Validate the new password
    auto policy = pImpl->mOptions.getPasswordPolicy();
    auto validationResult
        = policy.validate(std::pair {newPassword, userNameAndPassword.second});
    if (validationResult ==
        Password::PasswordPolicy::ValidationResult::TooShort)
    {
        return std::unexpected(ChangePasswordError::PasswordTooShort);
    }
    else if (validationResult ==
             Password::PasswordPolicy::ValidationResult::TooLong)
    {
        return std::unexpected(ChangePasswordError::PasswordTooLong);
    }
    else if (validationResult ==
             Password::PasswordPolicy::ValidationResult::NoNumber)
    {
        return std::unexpected(ChangePasswordError::PasswordNeedsNumber);
    }
    else if (validationResult ==
             Password::PasswordPolicy::ValidationResult::NoSpecialCharacter)
    {
        return std::unexpected(
            ChangePasswordError::PasswordNeedsSpecialCharacter);
    }
    else if (validationResult ==
             Password::PasswordPolicy::ValidationResult::PasswordsMatch)
    {
        return std::unexpected(
            ChangePasswordError::PasswordsMatch);
    }

    // Check user's password (but not do a full login)
    auto verifyPasswordResult = verifyPassword(userNameAndPassword);
    if (verifyPasswordResult.has_value())
    {
        std::string hashedPassword;
        try
        {
            hashedPassword = pImpl->mPasswordHasher->hash(newPassword);
        }
        catch (const std::exception &e)
        {
            SPDLOG_LOGGER_ERROR(
                pImpl->mLogger,
                "Failed to hash password; skpping password update");
            return std::unexpected(ChangePasswordError::ServerError);
        }
        if (hashedPassword.empty())
        {
            SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                "Resulting hashed password is empty");
            return std::unexpected(ChangePasswordError::ServerError);
        }
        try
        {
            auto wasSuccess = pImpl->changePassword(
                  std::pair {userNameAndPassword.first, hashedPassword}); 
            if (!wasSuccess)
            {
                // Indicates provisional password expired between the
                // verify and update.
                SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                    "Failed to update password for {}",
                                    userNameAndPassword.first);
                return std::unexpected(ChangePasswordError::Unauthenticated);
            }
            else
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                                   "{} updated password",
                                   userNameAndPassword.first);
            }
        }
        catch (const std::exception &e)
        {
            SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                "Failed to change password for {} because {}",
                                userNameAndPassword.first, e.what());
            return std::unexpected(ChangePasswordError::ServerError);
        }
    }
    else
    {
        if (verifyPasswordResult.error() ==
            IAuthenticator::Result::InvalidCredentials)
        {
            return std::unexpected(ChangePasswordError::Unauthenticated);
        }
        return std::unexpected(ChangePasswordError::ServerError);
    }
    return {};
}

/// Verify password
std::expected<void, IAuthenticator::Result>
UserLoginAuthority::verifyPassword(
    const std::pair<std::string, std::string> &userNameAndPassword) const
{
    if (!isInitialized())
    {       
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(IAuthenticator::Result::ServerError);
    }   
    auto user = userNameAndPassword.first;
    if (user.empty())
    {
        SPDLOG_LOGGER_DEBUG(pImpl->mLogger, "Cannot verify an empty user name");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
    auto password = userNameAndPassword.second;
    try
    {
        auto hashedPassword = pImpl->getHashedPasswordFromDatabase(user);
        if (hashedPassword != std::nullopt)
        {
            if (Password::Hasher::verify(password, *hashedPassword))
            {
                return {};
            }
            SPDLOG_LOGGER_DEBUG(pImpl->mLogger, "{} passwords do not match",
                                user);
            return std::unexpected(IAuthenticator::Result::InvalidCredentials);
        }
        else
        {   
            SPDLOG_LOGGER_WARN(pImpl->mLogger, "{} not in database", user);
            return std::unexpected(IAuthenticator::Result::InvalidCredentials);
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger, "Hit exception {}", e.what());
        return std::unexpected(IAuthenticator::Result::ServerError);           
    }   
    SPDLOG_LOGGER_ERROR(pImpl->mLogger, "Unhandled verify password workflow");
    return std::unexpected(IAuthenticator::Result::ServerError);
}

/// Add a key
std::expected<void, UserLoginAuthority::KeyError>
UserLoginAuthority::addKey(
    const std::pair<std::string, std::string> &userNameAndPassword,
    const std::string &keyName,
    const std::vector<unsigned char> &publicKey,
    const std::string &assertion,
    const std::optional<std::chrono::seconds> &expiresAfter)
{
    if (!isInitialized())
    {    
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(
           UserLoginAuthority::KeyError::ServerError);
    } 
    // Step 1: Authenticated?
    auto verificationResult = verifyPassword(userNameAndPassword);
    if (!verificationResult.has_value())
    {
        if (verificationResult.error() ==
            IAuthenticator::Result::InvalidCredentials)
        {
            return std::unexpected(
               UserLoginAuthority::KeyError::Unauthenticated);
        }
        else if (verificationResult.error() ==
                 IAuthenticator::Result::ServerError)
        {
            return std::unexpected(UserLoginAuthority::KeyError::ServerError);
        }
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
            "UserLoginAuthority could not classify verify password result");
        return std::unexpected(UserLoginAuthority::KeyError::ServerError);
    }
    // Get the corresponding normalized name from the database
    std::string userName;
    try
    { 
        auto userNameResult = pImpl->getUserName(userNameAndPassword.first);
        if (!userNameResult.has_value())
        {
            SPDLOG_LOGGER_ERROR(pImpl->mLogger,
            "UserLoginAuthority could not get user name from database");
            return std::unexpected(UserLoginAuthority::KeyError::ServerError);
        }
        userName = std::move(*userNameResult);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
           "UserLoginAuthority {} appears to have disappeared", 
           userNameAndPassword.first);
        return std::unexpected(UserLoginAuthority::KeyError::ServerError);
    }
    // Step 2: Verify signature (touch database above) 
    if (!::verifyAssertionSignature(publicKey, assertion))
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Rejecting proposed key; bad signature");
        return std::unexpected(UserLoginAuthority::KeyError::InvalidKey);
    }
    // Step 3: Check the claims - alg(orithm) is eddsa, aud(ience) is issuer,
    //         and now the time is within in a minute to ensure this is
    //         short-lived
    const auto claims
        = ::parseAssertion(assertion,
                           std::chrono::system_clock::now(),
                           pImpl->mOptions.getIssuer() + "/keys");
    if (claims == std::nullopt)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Rejecting key login; bad or expired assertion");
        return std::unexpected(UserLoginAuthority::KeyError::InvalidKey);
    }
    if (claims->subject != userName)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Claim does not belong to this user");
        return std::unexpected(UserLoginAuthority::KeyError::InvalidKey);
    }
    // Step 4: Add to database
    const auto &user = claims->subject;
    try
    {
        std::chrono::seconds expires{
            pImpl->mOptions.getMaximumLoginKeyTimeToLive()};
        if (expiresAfter != std::nullopt)
        {
            if (expiresAfter->count() < 1)
            {
                return std::unexpected(
                    UserLoginAuthority::KeyError::InvalidExpiration);
            }
            if (*expiresAfter > pImpl->mOptions.getMaximumLoginKeyTimeToLive())
            {
                return std::unexpected(
                    UserLoginAuthority::KeyError::InvalidExpiration);
            }
            expires = *expiresAfter;
        }
        std::chrono::seconds expires;
        auto added = pImpl->addUserKey(user,
                                       keyName,
                                       ::encodeBase64(publicKey),
                                       assertion,
                                       expires);
        if (!added)
        {
            SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                "{} vanished while adding key {}",
                                user, keyName);
            return std::unexpected(KeyError::ServerError);
        }
    }
    catch (const pqxx::insufficient_privilege &)
    {
        return std::unexpected(KeyError::PasswordChangeRequired);
    }
    catch (const pqxx::unique_violation &)
    {
        return std::unexpected(KeyError::KeyInUse);
    }
    catch (const pqxx::sql_error &e)
    {
        const std::string_view message{e.what()};
        if (e.sqlstate() == "42710")
        {
            return std::unexpected(KeyError::NameInUse);
        }
        if (e.sqlstate() == "22023")
        {
            if (message.find("invalid key name") != std::string_view::npos)
            {
                return std::unexpected(KeyError::InvalidName);
            }
            if (message.find("invalid expiration") != std::string_view::npos)
            {
                return std::unexpected(KeyError::InvalidExpiration);
            }
            return std::unexpected(KeyError::InvalidKey);
        }
        if (e.sqlstate() == "53400")
        {
            return std::unexpected(KeyError::TooManyKeys);
        }
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to add key because {}",
                            e.what());
        return std::unexpected(KeyError::ServerError);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to add key - unhandled exception {}",
                            e.what());
        return std::unexpected(KeyError::ServerError);
    }
    SPDLOG_LOGGER_INFO(pImpl->mLogger, "{} added key {}", userName, keyName);
    return {};
}

/// Change the user name and password
std::expected<void, UserLoginAuthority::KeyError>
UserLoginAuthority::revokeKey(
    const std::string &user,
    const std::string &keyName)
{
    if (!isInitialized())
    {    
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(
           UserLoginAuthority::KeyError::ServerError);
    }
    if (keyName.empty())
    {
        return std::unexpected(
           UserLoginAuthority::KeyError::NoKeyFound);
    } 

    return {};
}

/// Destructor
UserLoginAuthority::~UserLoginAuthority() = default;
