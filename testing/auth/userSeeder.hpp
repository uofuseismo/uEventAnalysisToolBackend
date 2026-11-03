#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_TESTING_AUTH_USER_SEEDER_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_TESTING_AUTH_USER_SEEDER_HPP
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
