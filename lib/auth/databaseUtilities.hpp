#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_DATABASE_UTILITIES_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_DATABASE_UTILITIES_HPP
#include <chrono>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <pqxx/pqxx>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include "uEventAnalysisToolBackend/database/credentials.hpp"

namespace UEventAnalysisToolBackend::Auth::Detail::DatabaseConnection 
{

class Database
{
protected:
    // Only usable as a base class
    ~Database()
    {   
        disconnect();
    }   

public:
    Database
    (
        const std::string &loggerName,
        const UEventAnalysisToolBackend::Database::Credentials &credentials,
        std::shared_ptr<spdlog::logger> logger
    ) :
        mCredentials(credentials),
        mLogger(std::move(logger))
    {
        if (mLogger == nullptr)
        {
            // NOLINTBEGIN(misc-include-cleaner)
            // N.B. stdout_color_mt throws if the name is already registered.
            auto loggerHandle = spdlog::get(loggerName);
            if (loggerHandle == nullptr)
            {
                mLogger = spdlog::stdout_color_mt(loggerName);
            }
            else
            {
                mLogger = loggerHandle;
            }
            // NOLINTEND(misc-include-cleaner)
        }
    }

    /// @brief Connect to the database.
    void connect()
    {       
        const std::scoped_lock lock(mDatabaseMutex);
        connectLocked();
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

    /// @brief Connect to the database
    /// @note The calling function must own the mutex.
    void connectLocked()
    {
        disconnectLocked();
        auto connectionString = mCredentials.getConnectionString();
        auto schema = mCredentials.getSchema();
        
        mConnection = std::make_unique<pqxx::connection> (connectionString);
        if (mConnection)
        {
            if (!mConnection->is_open())
            {
                throw std::runtime_error(
                    "Failed to establish database connection to "
                   + mCredentials.getDatabaseName()
                   + " at " + mCredentials.getHost());
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
                                   + mCredentials.getDatabaseName()
                                   + " at " + mCredentials.getHost());
        }
        SPDLOG_LOGGER_DEBUG(mLogger, 
                            "Connected to {} at {}",
                            mCredentials.getDatabaseName(),
                            mCredentials.getHost());
    }

    /// @brief Disconnect from the database
    void disconnect()
    {
        const std::scoped_lock lock(mDatabaseMutex);
        disconnectLocked();
    }   

    /// @brief Disconnect from the database
    /// @note Caller must hold mDatabaseMutex.
    void disconnectLocked()
    {
        if (mConnection)
        {
            mConnection->close();
            mConnection = nullptr;
        }
    }

    /// @brief Runs f(transaction) under the lock.  On a broken connection,
    ///        reconnects and retries once.  f must commit.
    template<typename F>
    decltype(auto) withTransaction(F &&f)
    {
        const std::scoped_lock lock(mDatabaseMutex);
        for (int attempt = 0;
             attempt < static_cast<int> (mRetrySchedule.size());
             ++attempt)
        {
            try
            {
                if (!mConnection || !mConnection->is_open())
                {
                    connectLocked();  // connect() minus its own locking
                }
                pqxx::work transaction(*mConnection);
                return f(transaction);
            }
            catch (const pqxx::broken_connection &e)
            {
                mConnection.reset();
                if (attempt < static_cast<int> (mRetrySchedule.size()) - 1)
                {
                    auto waitFor = mRetrySchedule[attempt + 1];
                    SPDLOG_LOGGER_WARN(mLogger,
                    "Lost database connection ({}); reconnecting in {} milliseconds",
                    e.what(), waitFor.count());
                    std::this_thread::sleep_for(waitFor);
                }
            }
        }
        SPDLOG_LOGGER_WARN(mLogger,
                           "Max reconnection attempts of {} hit",
                            mRetrySchedule.size());
        throw std::runtime_error("Database connection error");
    }

    // Get rid of some stuff
    Database() = delete;
    Database(const Database &) = delete;
    Database(Database &&) noexcept = delete;
    Database& operator=(const Database &) = delete;
    Database& operator=(Database &&) noexcept = delete;
//public:
    UEventAnalysisToolBackend::Database::Credentials mCredentials;
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    mutable std::mutex mDatabaseMutex;
    std::unique_ptr<pqxx::connection> mConnection{nullptr};
    std::vector<std::chrono::milliseconds> mRetrySchedule
    {
        std::chrono::seconds {0},
        std::chrono::seconds {2}, 
        std::chrono::seconds {15}
    };
};

}
#endif
