#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_TESTING_AUTH_USER_SEEDER_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_TESTING_AUTH_USER_SEEDER_HPP
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <pqxx/pqxx>
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/database/credentials.hpp"

// Seeds the users the [.integration] auth tests log in as, and removes
// them again, through a superuser connection: auth.add_user and friends
// are granted to no role.

namespace IntegrationDatabase
{

/// @result The cheapest hash settings libsodium allows.  Verify reads the
///         cost from the hash itself, so this only matters for rehashing.
[[nodiscard]] inline UEventAnalysisToolBackend::Auth::Password::HasherOptions
    cheapHasherOptions()
{
    UEventAnalysisToolBackend::Auth::Password::HasherOptions options;
    options.setMemoryLimitInBytes(8192);
    return options;
}

class UserSeeder
{
public:
    UserSeeder(const UEventAnalysisToolBackend::Database::Credentials &credentials,
               const std::string &password) :
        mConnection(std::make_unique<pqxx::connection>
                    (credentials.getConnectionString())),
        mHash(UEventAnalysisToolBackend::Auth::Password::Hasher
              {cheapHasherOptions()}.hash(password))
    {
    }
    void addUser(const std::string &name, const bool isAdministrator)
    {
        pqxx::work transaction{*mConnection};
        const auto added
            = transaction.exec("SELECT auth.add_user($1, $2, $3)",
                               pqxx::params {name, mHash, isAdministrator})
                         .one_row()[0].as<bool> ();
        transaction.commit();
        if (!added){throw std::runtime_error("Could not add " + name);}
        mNames.push_back(name);
    }
    /// @brief A user still holding an issued password.
    void addProvisionalUser(const std::string &name,
                            const bool isAdministrator = false)
    {
        pqxx::work transaction{*mConnection};
        const auto added
            = transaction.exec(
                  "SELECT auth.add_provisional_user($1, $2, INTERVAL '1 hour')",
                  pqxx::params {name, mHash}).one_row()[0].as<bool> ();
        if (isAdministrator)
        {
            // There is no ungated function for this, so set the column.
            transaction.exec("UPDATE auth.users SET is_admin = TRUE "
                             " WHERE name = $1",
                             pqxx::params {name});
        }
        transaction.commit();
        if (!added){throw std::runtime_error("Could not add " + name);}
        mNames.push_back(name);
    }
    /// @brief Lapses a provisional user's issued password, as if the
    ///        window had passed.
    void expireProvisionalPassword(const std::string &name)
    {
        pqxx::work transaction{*mConnection};
        transaction.exec("UPDATE auth.users "
                         "   SET provisional_until = NOW() - INTERVAL '1 second'"
                         " WHERE name = $1",
                         pqxx::params {name});
        transaction.commit();
    }
    void setPermission(const std::string &name,
                       const std::string &schema,
                       const std::string &permission)
    {
        pqxx::work transaction{*mConnection};
        const auto set
            = transaction.exec("SELECT auth.set_user_permission($1, $2, $3)",
                               pqxx::params {name, schema, permission})
                         .one_row()[0].as<bool> ();
        transaction.commit();
        if (!set)
        {
            throw std::runtime_error("Could not grant " + name + " "
                                   + permission + " on " + schema);
        }
    }
    /// @brief Registers a public key, in the encoded form auth.user_keys
    ///        stores.  It goes when the user does.
    /// @param expiresInSeconds  If set, the key expires this long from now.
    void addKey(const std::string &name,
                const std::string &keyName,
                const std::string &encodedPublicKey,
                const std::optional<int> expiresInSeconds = std::nullopt)
    {
        pqxx::work transaction{*mConnection};
        // NOW() + NULL is NULL: no expiry.
        const auto added
            = transaction.exec("SELECT auth.add_user_key($1, $2, $3, 'ed25519',"
                               "  NOW() + make_interval(secs => $4))",
                               pqxx::params {name, keyName, encodedPublicKey,
                                             expiresInSeconds})
                         .one_row()[0].as<bool> ();
        transaction.commit();
        if (!added)
        {
            throw std::runtime_error("Could not add key " + keyName
                                   + " for " + name);
        }
    }
    void revokeKey(const std::string &name, const std::string &keyName)
    {
        pqxx::work transaction{*mConnection};
        transaction.exec("SELECT auth.revoke_user_key($1, $2)",
                         pqxx::params {name, keyName});
        transaction.commit();
    }
    /// @result True if the key's last_used has been set.
    [[nodiscard]] bool keyHasBeenUsed(const std::string &name,
                                      const std::string &keyName)
    {
        pqxx::nontransaction transaction{*mConnection};
        const auto row
            = transaction.exec("SELECT last_used FROM auth.list_user_keys($1)"
                               " WHERE key_name = $2",
                               pqxx::params {name, keyName}).one_row();
        return !row[0].is_null();
    }
    /// @result True if the key has been revoked.
    [[nodiscard]] bool keyIsRevoked(const std::string &name,
                                    const std::string &keyName)
    {
        pqxx::nontransaction transaction{*mConnection};
        const auto row
            = transaction.exec("SELECT revoked FROM auth.list_user_keys($1)"
                               " WHERE key_name = $2",
                               pqxx::params {name, keyName}).one_row();
        return !row[0].is_null();
    }
    /// @result The fingerprint the database lists for the key.
    [[nodiscard]] std::string keyFingerprint(const std::string &name,
                                             const std::string &keyName)
    {
        pqxx::nontransaction transaction{*mConnection};
        return transaction.exec("SELECT fingerprint"
                                "  FROM auth.list_user_keys($1)"
                                " WHERE key_name = $2",
                                pqxx::params {name, keyName})
                          .one_row()[0].as<std::string> ();
    }
    /// @result True if the user has a key by this name, active or not.
    [[nodiscard]] bool hasKey(const std::string &name,
                              const std::string &keyName)
    {
        pqxx::nontransaction transaction{*mConnection};
        return transaction.exec("SELECT EXISTS (SELECT 1"
                                "  FROM auth.list_user_keys($1)"
                                " WHERE key_name = $2)",
                                pqxx::params {name, keyName})
                          .one_row()[0].as<bool> ();
    }
    /// @result How long until the key expires, or nothing if it never does.
    [[nodiscard]] std::optional<std::chrono::seconds>
        keyExpiresIn(const std::string &name, const std::string &keyName)
    {
        pqxx::nontransaction transaction{*mConnection};
        const auto row
            = transaction.exec("SELECT EXTRACT(EPOCH FROM expires - NOW())"
                               "         ::BIGINT"
                               "  FROM auth.list_user_keys($1)"
                               " WHERE key_name = $2",
                               pqxx::params {name, keyName}).one_row();
        if (row[0].is_null()){return std::nullopt;}
        return std::chrono::seconds {row[0].as<int64_t> ()};
    }
    /// @brief Removes a user someone else created - e.g., the class under
    ///        test - along with the seeded ones.
    void track(const std::string &name)
    {
        mNames.push_back(name);
    }
    /// @result True if the user exists at all.
    [[nodiscard]] bool exists(const std::string &name)
    {
        pqxx::nontransaction transaction{*mConnection};
        return transaction.exec("SELECT auth.get_user_name($1) IS NOT NULL",
                                pqxx::params {name})
                          .one_row()[0].as<bool> ();
    }
    /// @result True if the user's is_admin flag is set.  Not
    ///         auth.user_is_admin, which also demands an activated user.
    [[nodiscard]] bool isAdministrator(const std::string &name)
    {
        return column(name, "is_admin") == std::optional<std::string> {"true"};
    }
    /// @result The number of activated administrators in the database.
    [[nodiscard]] int countActiveAdministrators()
    {
        pqxx::nontransaction transaction{*mConnection};
        return transaction.exec("SELECT auth.count_active_admins()")
                          .one_row()[0].as<int> ();
    }
    /// @result True if the user's last_login has been set.
    [[nodiscard]] bool hasLoggedIn(const std::string &name)
    {
        return column(name, "last_login").has_value();
    }
    /// @result True if the user has ever changed an issued password.
    [[nodiscard]] bool isActivated(const std::string &name)
    {
        return column(name, "activated").has_value();
    }
    /// @result True if the user still holds an issued password.
    [[nodiscard]] bool isProvisional(const std::string &name)
    {
        return column(name, "provisional_until").has_value();
    }
    /// @result The stored hash, read directly - not through
    ///         auth.get_password_hash, which hides expired ones.
    [[nodiscard]] std::string passwordHash(const std::string &name)
    {
        return column(name, "password_hash").value_or(std::string {});
    }
    ~UserSeeder()
    {
        for (const auto &name : mNames)
        {
            try
            {
                pqxx::work transaction{*mConnection};
                transaction.exec("SELECT auth.remove_user($1)",
                                 pqxx::params {name});
                transaction.commit();
            }
            catch (const std::exception &e)
            {
                // Can't fail the test from a destructor; say so instead.
                // The suffix keeps a leftover row from colliding with the
                // next run.
                std::cerr << "Could not remove test user " << name
                          << ": " << e.what() << '\n';
            }
        }
    }
    UserSeeder(const UserSeeder &) = delete;
    UserSeeder(UserSeeder &&) = delete;
    UserSeeder& operator=(const UserSeeder &) = delete;
    UserSeeder& operator=(UserSeeder &&) = delete;
private:
    /// @result The column as text, or nothing if it is null.
    /// @note The column name is never user input.
    [[nodiscard]] std::optional<std::string>
        column(const std::string &name, const std::string &columnName)
    {
        pqxx::nontransaction transaction{*mConnection};
        const auto result
            = transaction.exec("SELECT " + columnName + "::TEXT"
                               "  FROM auth.users WHERE name = $1",
                               pqxx::params {name});
        const auto row = result.one_row();
        if (row[0].is_null()){return std::nullopt;}
        return row[0].as<std::string> ();
    }
    std::unique_ptr<pqxx::connection> mConnection;
    std::vector<std::string> mNames;
    std::string mHash;
};

}
#endif
