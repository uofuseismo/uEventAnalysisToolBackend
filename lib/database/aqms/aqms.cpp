#include <iostream>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <pqxx/pqxx>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include "uEventAnalysisToolBackend/database/aqms/aqms.hpp"
#include "uEventAnalysisToolBackend/database/credentials.hpp"
#include "uEventAnalysisToolBackend/database/aqms/event.hpp"
#include "uEventAnalysisToolBackend/database/aqms/origin.hpp"
#include "uEventAnalysisToolBackend/database/aqms/arrival.hpp"
#include "uEventAnalysisToolBackend/database/aqms/streamIdentifier.hpp"


using namespace UEventAnalysisToolBackend::Database::AQMS;

namespace
{

Event::EventType toEventType(const std::string &eventType)
{
    if (eventType == "eq")
    {
        return Event::EventType::Earthquake;
    }
    else if (eventType == "qb")
    {
        return Event::EventType::QuarryBlast;
    }
    else if (eventType == "st")
    {
        return Event::EventType::SubnetTrigger;
    }
    else if (eventType == "av")
    {
        return Event::EventType::Avalanche;
    }
    else if (eventType == "co")
    {
        return Event::EventType::Collapse;
    }
    else if (eventType == "ex")
    {
        return Event::EventType::Explosion;
    }
    else if (eventType == "mi")
    {
        return Event::EventType::MiningInduced;
    }
    else if (eventType == "nt")
    {
        return Event::EventType::NuclearTest;
    }
    else if (eventType == "so")
    {
        return Event::EventType::Sonic;
    }
    else if (eventType == "uk")
    {
        return Event::EventType::Unknown;
    }
    throw std::invalid_argument("Unhandled event type " + eventType); 
}

Origin::GeographicType toGeographicType(const std::string &gtype)
{
    if (gtype == "l")
    {
        return Origin::GeographicType::Local;
    }
    else if (gtype == "r")
    {
        return Origin::GeographicType::Regional;
    }
    else if (gtype  == "t")
    {
        return Origin::GeographicType::Teleseismic;
    }
    throw std::runtime_error("Unhandled geographic type " + gtype);
}

Origin::ReviewStatus toOriginReviewStatus(const std::string &rflag)
{
    if (rflag == "A")
    {
        return Origin::ReviewStatus::Automatic;
    }
    else if (rflag == "C")
    {
        return Origin::ReviewStatus::Cancelled;
    }
    else if (rflag == "H")
    {
        return Origin::ReviewStatus::Human;
    }
    else if (rflag == "F")
    {
        return Origin::ReviewStatus::Finalized;
    }
    else if (rflag == "I")
    {
        return Origin::ReviewStatus::Incomplete;
    }
    throw std::runtime_error("Unhandled origin review status " + rflag); 
}

Arrival::Phase toArrivalPhase(const std::string &phase)
{
    if (phase == "P")
    {
        return Arrival::Phase::P;
    }
    else if (phase == "S")
    {
        return Arrival::Phase::S;
    }
    throw std::runtime_error("Unhandled phase type " + phase);
}

Arrival::ReviewStatus toArrivalReviewStatus(const std::string &rflag)
{
    if (rflag == "A")
    {
        return Arrival::ReviewStatus::Automatic;
    }
    else if (rflag == "H")
    {
        return Arrival::ReviewStatus::Human;
    }
    throw std::runtime_error("Unhandled arrival review flag " + rflag);
}

}

class AQMS::AQMSImpl
{
public:
    AQMSImpl(const UEventAnalysisToolBackend::Database::Credentials &credentials,
             const AQMS::Region region,
             std::shared_ptr<spdlog::logger> logger) :
        mCredentials(credentials),
        mRegion(region),
        mLogger(std::move(logger))
    {
        if (!mCredentials.hasUser())
        {
            throw std::invalid_argument("User not set in credentials");
        }
        if (!mCredentials.hasPassword())
        {
            throw std::invalid_argument("Password not set in credentials");
        }
        if (!mCredentials.hasDatabaseName())
        {
            throw std::invalid_argument("Database name not set in credentials");
        }
        if (mLogger == nullptr)
        {
            // NOLINTBEGIN(misc-include-cleaner)
            constexpr const char *loggerName{"AQMSDatabaseConsole"};
            mLogger = spdlog::get(loggerName);
            if (mLogger == nullptr)
            {
                mLogger = spdlog::stdout_color_mt(loggerName);
            }
            // NOLINTEND(misc-include-cleaner)
        }
        connect();
        mInitialized = isConnected();
    }

    /// @brief Connect to the database
    void connect()
    {
        disconnect();
        auto connectionString = mCredentials.getConnectionString();
        auto schema = mCredentials.getSchema();
        {
        const std::scoped_lock lock(mDatabaseMutex);
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
        }
        SPDLOG_LOGGER_INFO(mLogger, 
                           "Connected to {} at {}",
                           mCredentials.getDatabaseName(),
                           mCredentials.getHost());
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

    [[nodiscard]] std::vector<Event> 
        timeRangeCatalogQuery(const std::pair<std::chrono::nanoseconds,
                                              std::chrono::nanoseconds> &startAndEndTime) const
    {   
        std::vector<Event> events;
SPDLOG_LOGGER_INFO(mLogger, "Starting time range query");
        // Nanoseconds to seconds 
        constexpr double nanoSecondsToSeconds{1.e-9};
        auto startTime
            = static_cast<double> (startAndEndTime.first.count())
             *nanoSecondsToSeconds;
        auto endTime 
            = static_cast<double> (startAndEndTime.second.count())
             *nanoSecondsToSeconds; 
        if (startTime > endTime)
        {
            throw std::invalid_argument("Start time cannot exceed end time");
        }
        std::map<int64_t, Event> eventsMap;
        std::map<int64_t, std::pair<int64_t, Origin>> originsMap;
        const pqxx::params parameters{startTime, endTime};
        const std::string_view eventOriginArrivalQuery{
R"""(
SELECT 
    event.evid as event_identifier,
    event.etype as event_type,
    event.prefor as event_preferred_origin,
    origin.orid as origin_identifier,
    origin.lat as origin_latitude, 
    origin.lon as origin_longitude,
    origin.depth as origin_depth_km,
    TrueTime.getEpoch(origin.datetime, 'NOMINAL') as origin_time,
    origin.gtype as origin_gtype,
    origin.rflag as origin_review
  FROM event
  INNER JOIN origin ON event.evid = origin.evid
  WHERE origin.datetime BETWEEN TrueTime.nominal2truef($1) AND TrueTime.nominal2truef($2)
   ORDER BY event.evid, origin.orid ASC;
)"""
        };
        Event currentEvent;
        std::vector<Origin> origins;
        int64_t oldEventIdentifier{-1};
        {
        const std::lock_guard<std::mutex> lock(mDatabaseMutex);
        pqxx::work transaction{*mConnection};
        pqxx::result result = transaction.exec(eventOriginArrivalQuery, parameters);
        for (const auto &row : result)
        {
            try
            {
            }
            catch (const std::exception &e)
            {
                SPDLOG_LOGGER_WARN(mLogger,
                                   "Failed creating event because {}",
                                   e.what());
            }
       }
       }
       return events;
    }

    [[nodiscard]] std::vector<Event> 
        timeRangeQuery(const std::pair<std::chrono::nanoseconds,
                                       std::chrono::nanoseconds> &startAndEndTime) const
    {
        std::vector<Event> events;
SPDLOG_LOGGER_INFO(mLogger, "Starting time range query");
        // Nanoseconds to seconds 
        constexpr double nanoSecondsToSeconds{1.e-9};
        auto startTime
            = static_cast<double> (startAndEndTime.first.count())
             *nanoSecondsToSeconds;
        auto endTime 
            = static_cast<double> (startAndEndTime.second.count())
             *nanoSecondsToSeconds; 
        if (startTime > endTime)
        {
            throw std::invalid_argument("Start time cannot exceed end time");
        }
        std::map<int64_t, Event> eventsMap;
        std::map<int64_t, std::pair<int64_t, Origin>> originsMap;
        //std::map<int64_t, std::vector<Arrival>> arrivalsMap;
        const pqxx::params parameters{startTime, endTime};
        const std::string_view eventOriginQuery{
R"""(
SELECT 
    event.evid as event_identifier,
    event.etype as event_type,
    event.prefor as event_preferred_origin,
    origin.orid as origin_identifier,
    origin.lat as origin_latitude, 
    origin.lon as origin_longitude,
    origin.depth as origin_depth_km,
    TrueTime.getEpoch(origin.datetime, 'NOMINAL') as origin_time,
    origin.gtype as origin_geographic_type,
    origin.rflag as origin_review_status
  FROM event
  INNER JOIN origin ON event.evid = origin.evid
  WHERE origin.datetime BETWEEN TrueTime.nominal2truef($1) AND TrueTime.nominal2truef($2);
)"""};
        bool startedBuildingArrivalsQuery{false};
        std::string arrivalsQuery{
R"""(
SELECT
    assocaro.orid AS origin_identifier,
    arrival.arid AS arrival_identifier,
    arrival.net as arrival_network,
    arrival.sta as arrival_station,
    arrival.seedchan as arrival_channel,
    arrival.location as arrival_location,
    TrueTime.getEpoch(arrival.datetime, 'NOMINAL') as arrival_time,
    arrival.iphase as arrival_phase,
    arrival.quality as arrival_quality,
    assocaro.timeres as arrival_residual,
    arrival.rflag as arrival_review_status
  FROM arrival
  INNER JOIN assocaro ON assocaro.arid = arrival.arid
  WHERE assocaro.orid IN (
)"""};
        {
        const std::lock_guard<std::mutex> lock(mDatabaseMutex);
        pqxx::work transaction{*mConnection};
        for (const auto &row :
             transaction.exec(eventOriginQuery, parameters))
        {
            try
            {
                auto eventIdentifier = row["event_identifier"].as<int64_t> ();
                auto edx = eventsMap.find(eventIdentifier);
                if (edx == eventsMap.end())
                {
                    Event event;
                    auto eventType = ::toEventType(row["event_type"].as<std::string>());
                    event.setEventType(eventType);
                    eventsMap.insert_or_assign(
                        eventIdentifier, std::move(event));
                }

                auto originIdentifier = row["origin_identifier"].as<int64_t> ();
                // Build origin if needed
                auto odx = originsMap.find(originIdentifier);
                if (odx == originsMap.end())
                {
                    auto preferredOrigin
                        = row["event_preferred_origin"].as<int64_t> ();
                    auto isPreferred
                        = (preferredOrigin == originIdentifier) ? true : false;
                    auto latitude = row["origin_latitude"].as<double> ();
                    auto longitude = row["origin_longitude"].as<double> ();
                    auto depth = row["origin_depth_km"].as<double> ()*1.e3;
                    auto originTime = 
                        std::chrono::nanoseconds
                        {
                            static_cast<int64_t>
                               (row["origin_time"].as<double> ()*1e9)
                        };
                    auto geographicType = Origin::GeographicType::Unknown;
                    try
                    {
                        geographicType
                            = ::toGeographicType(
                                   row["origin_geographic_type"].as<std::string> ());
                    }
                    catch (...)
                    {
                    }
                    auto originReviewStatus
                        = ::toOriginReviewStatus(
                              row["origin_review_status"].as<std::string> ());
                    Origin origin;
 
                    origin.setIdentifier(originIdentifier);
                    origin.setLatitude(latitude);
                    origin.setLongitude(longitude);
                    origin.setDepth(depth);
                    origin.setTime(originTime);
                    origin.setGeographicType(geographicType);
                    origin.setReviewStatus(originReviewStatus);
                    origin.setNotPreferred();
                    if (isPreferred){origin.setIsPreferred();}
                    std::pair<int64_t, Origin>
                        insertPair{eventIdentifier, std::move(origin)};
                    originsMap.insert_or_assign(
                        originIdentifier, std::move(insertPair));
                    if (startedBuildingArrivalsQuery)
                    {
                        arrivalsQuery = arrivalsQuery.append(", ").append(std::to_string(originIdentifier));
                    }
                    else
                    {
                        arrivalsQuery.append(std::to_string(originIdentifier));
                        startedBuildingArrivalsQuery = true;
                    }
                }
            }
            catch (const std::exception &e)
            {
                SPDLOG_LOGGER_WARN(mLogger, "Failed to unpack row because {}",
                                   e.what());
            }
        }
        // Get the arrivals
        arrivalsQuery = arrivalsQuery.append(") ORDER by origin_identifier, arrival_time ASC;");
        //std::cout << arrivalsQuery << std::endl;
        std::map<int64_t, std::vector<Arrival>> arrivalsMap;
        for (const auto &row : transaction.exec(arrivalsQuery))
        {
            try
            {
                auto originIdentifier = row["origin_identifier"].as<int64_t> ();
                auto arrivalIdentifier = row["arrival_identifier"].as<int64_t> ();
                auto network = row["arrival_network"].as<std::string> ();
                auto station = row["arrival_station"].as<std::string> ();
                auto channel = row["arrival_channel"].as<std::string> ();
                auto locationCode = row["arrival_location"].as<std::string> ("--");
                auto arrivalTime = 
                    std::chrono::nanoseconds
                    {
                        static_cast<int64_t> (row["arrival_time"].as<double> ()*1e9)
                    };
                auto phase = ::toArrivalPhase(row["arrival_phase"].as<std::string> ());
                auto arrivalQuality = row["arrival_quality"].as<double> ();
                auto arrivalResidual =
                    std::chrono::nanoseconds
                    {
                        static_cast<int64_t> (row["arrival_residual"].as<double> ()*1e9)
                    };
                auto arrivalReviewStatus
                    = ::toArrivalReviewStatus(row["arrival_review_status"].as<std::string> ());

                StreamIdentifier streamIdentifier;
                streamIdentifier.setNetwork(network);
                streamIdentifier.setStation(station);
                streamIdentifier.setChannel(channel);
                streamIdentifier.setLocationCode(locationCode);

                Arrival arrival;
                arrival.setIdentifier(arrivalIdentifier);
                arrival.setStreamIdentifier(std::move(streamIdentifier));
                arrival.setTime(arrivalTime);
                arrival.setPhase(phase);
                arrival.setQuality(arrivalQuality);
                arrival.setReviewStatus(arrivalReviewStatus);

                auto adx = arrivalsMap.find(originIdentifier);
                if (adx == arrivalsMap.end())
                {
                    std::vector<Arrival> arrivals{std::move(arrival)};
                    arrivalsMap.insert_or_assign(originIdentifier, std::move(arrivals));
                }
                else
                {
                    adx->second.push_back(std::move(arrival));
                }
            }
            catch (const std::exception &e)
            {
                SPDLOG_LOGGER_WARN(mLogger, "Failed to get arrival because {}",
                                   e.what());
            }
        }
        // Put the arrivals on the origins
        for (auto &originPair : originsMap)
        {
            auto originIdentifier = originPair.first;
            auto adx = arrivalsMap.find(originIdentifier);
            // Sometimes origins don't have arrivals apparently - "processed"
            // teleseismic events can have this
            if (adx != arrivalsMap.end())
            { 
                try
                {
                    originPair.second.second.setArrivals(
                        std::move(adx->second)); 
                }
                catch (const std::exception &e)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                        "Failed to set arrivals on origin because {}",
                        e.what());
                }
            }
        }
       
/*
        // Assign arrivals to origins
        for (auto &originPair : originsMap)
        {
            auto &origin = originPair.second.second;
            auto adx = arrivalsMap.find(origin.getIdentifier());
            if (adx != arrivalsMap.end())
            {
                try
                {
                    origin.setArrivals(std::move(adx->second));
                }
                catch (const std::exception &e)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                                       "Failed to add arrivals because {}",
                                       e.what());
                }
            }
            else
            {
                SPDLOG_LOGGER_WARN(mLogger,
                                   "Failed arrivals for origin");
            }
        }
*/
        // Construct the events in two steps:
        // The originsMap is (orid, {evid, origin}).  I need to reformat this 
        // to (evid, vector<origins>)
        std::map<int64_t, std::vector<Origin>> eventsToOriginsMap; 
        for (auto &originPair : originsMap)
        {
            auto eventIdentifier = originPair.second.first;
            auto edx = eventsToOriginsMap.find(eventIdentifier);
            if (edx == eventsToOriginsMap.end())
            {
                std::vector<Origin> origins{std::move(originPair.second.second)};
                eventsToOriginsMap.insert_or_assign(
                   eventIdentifier, std::move(origins));
            }
            else
            {
                edx->second.push_back(std::move(originPair.second.second));
            }
        }
        events.reserve(eventsMap.size());
        for (auto &eventOriginPair : eventsToOriginsMap)
        {
            auto eventIdentifier = eventOriginPair.first;
            auto edx = eventsMap.find(eventIdentifier);
            if (edx != eventsMap.end()) 
            {
                try
                {
                    edx->second.setOrigins(std::move(eventOriginPair.second));
                    events.push_back(std::move(edx->second));
                }
                catch (const std::exception &e)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                       "Couldn't add origins to {} because {}",
                       eventIdentifier,
                       e.what());
                }
            }
            else
            {
                SPDLOG_LOGGER_WARN(mLogger, "Couldn't find event in map");
            }
        }
        transaction.commit();
        }
        // Sort time ascending
        std::sort(events.begin(), events.end(), 
                  [](const auto &lhs, const auto &rhs)
                  {
                      auto lhsTime = lhs.getPreferredOrigin().getTime();
                      auto rhsTime = rhs.getPreferredOrigin().getTime();
                      return lhsTime < rhsTime;
                  });
        // Okay, there's a logical bug here - technically an event could have
        // updated so we'll have a stale read.  I should put this in the 
        // transaction.

        SPDLOG_LOGGER_INFO(mLogger, "Finishing query with {} events",
                           events.size());
        return events;
    }
//private:
    UEventAnalysisToolBackend::Database::Credentials mCredentials;
    AQMS::Region mRegion{AQMS::Region::All};
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    mutable std::mutex mDatabaseMutex;
    std::unique_ptr<pqxx::connection> mConnection{nullptr};
    bool mInitialized{false};
};

/// Constructor
AQMS::AQMS(const UEventAnalysisToolBackend::Database::Credentials &credentials,
           const Region region,
           std::shared_ptr<spdlog::logger> logger) :
    pImpl(std::make_unique<AQMSImpl> (credentials, region, std::move(logger)))
{
}

AQMS::AQMS(const UEventAnalysisToolBackend::Database::Credentials &credentials,
           std::shared_ptr<spdlog::logger> logger) :
    pImpl(std::make_unique<AQMSImpl> (credentials, 
                                      Region::All,
                                      std::move(logger)))
{
}

/// Destructor
AQMS::~AQMS() = default;

/// Get events
std::vector<Event>
AQMS::getEvents(const std::chrono::nanoseconds &startTime) const
{
     auto endTime
         = std::chrono::duration_cast<std::chrono::nanoseconds>
           ((std::chrono::high_resolution_clock::now()).time_since_epoch());
     endTime = std::max(endTime, startTime + std::chrono::nanoseconds {1});
     return getEvents(std::pair {startTime, endTime}); 
}


std::vector<Event>
AQMS::getEvents(
    const std::pair<std::chrono::nanoseconds,
                    std::chrono::nanoseconds> &startAndEndTime) const
{
    if (!isInitialized())
    {
        throw std::invalid_argument("Class not initialized");
    }
    if (startAndEndTime.first > startAndEndTime.second)
    {
        throw std::invalid_argument("Start time must be less than end time");
    }
    return pImpl->timeRangeQuery(startAndEndTime);
}

/// Initialized?
bool AQMS::isInitialized() const noexcept
{
    return pImpl->mInitialized;
}
