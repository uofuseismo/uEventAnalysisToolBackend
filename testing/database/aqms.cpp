#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include "uEventAnalysisToolBackend/database/aqms/streamIdentifier.hpp"
#include "uEventAnalysisToolBackend/database/aqms/arrival.hpp"
#include "uEventAnalysisToolBackend/database/aqms/magnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/localMagnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/durationMagnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/humanMagnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/origin.hpp"
#include "uEventAnalysisToolBackend/database/aqms/event.hpp"
#include "uEventAnalysisToolBackend/database/aqms/peakToPeakAmplitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/stationLocalMagnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/stationDurationMagnitude.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

namespace
{

/// @brief Builds a fully-populated stream identifier for reuse in tests.
StreamIdentifier makeStreamIdentifier()
{
    StreamIdentifier streamIdentifier;
    streamIdentifier.setNetwork("UU");
    streamIdentifier.setStation("CTU");
    streamIdentifier.setChannel("HHZ");
    streamIdentifier.setLocationCode("01");
    return streamIdentifier;
}

/// @brief Builds an origin with all fields required by Event::setOrigins.
//NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
Origin makeValidOrigin(const double latitude = 40.77,
                       const double longitude = -111.89,
                       const double depth = 5000,
                       const int64_t identifier = 3233)
{
    Origin origin;
    origin.setIdentifier(identifier);
    origin.setLatitude(latitude);
    origin.setLongitude(longitude);
    origin.setDepth(depth);
    origin.setTime(std::chrono::nanoseconds{1'700'000'000'000'000'000});
    return origin;
}

/// @brief Builds a valid magnitude set: a preferred local magnitude and a
///        non-preferred duration magnitude.
std::vector<std::unique_ptr<IMagnitude>> makeMagnitudes()
{
    auto local = std::make_unique<LocalMagnitude> ();
    local->setValue(3.4);
    local->setIsPreferred();

    auto duration = std::make_unique<DurationMagnitude> ();
    duration->setValue(3.1);
    duration->setNotPreferred();

    std::vector<std::unique_ptr<IMagnitude>> magnitudes;
    magnitudes.push_back(std::move(local));
    magnitudes.push_back(std::move(duration));
    return magnitudes;
}

/// @brief Builds a stream identifier on the given channel of UU.CTU.
StreamIdentifier makeStream(const std::string &channel)
{
    StreamIdentifier streamIdentifier;
    streamIdentifier.setNetwork("UU");
    streamIdentifier.setStation("CTU");
    streamIdentifier.setChannel(channel);
    streamIdentifier.setLocationCode("01");
    return streamIdentifier;
}

/// @brief Builds a fully-populated peak-to-peak amplitude (millimeters).
PeakToPeakAmplitude makeAmplitude(const std::string &channel,
                                  const double amplitudeMillimeters)
{
    PeakToPeakAmplitude amplitude;
    amplitude.setStreamIdentifier(makeStream(channel));
    const std::pair<std::chrono::nanoseconds, std::chrono::nanoseconds>
        peakTimes{std::chrono::nanoseconds{1}, std::chrono::nanoseconds{2}};
    amplitude.setPeakTimes(peakTimes);
    amplitude.setAmplitude(amplitudeMillimeters,
                           PeakToPeakAmplitude::Units::Millimeters);
    return amplitude;
}

}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::StreamIdentifier", "StreamIdentifier")
{
    SECTION("Defaults")
    {
        const StreamIdentifier streamIdentifier;
        REQUIRE_FALSE(streamIdentifier.hasNetwork());
        REQUIRE_FALSE(streamIdentifier.hasStation());
        REQUIRE_FALSE(streamIdentifier.hasChannel());
        REQUIRE_FALSE(streamIdentifier.hasLocationCode());
        REQUIRE_THROWS_AS(streamIdentifier.getNetwork(), std::runtime_error);
        REQUIRE_THROWS_AS(streamIdentifier.getStation(), std::runtime_error);
        REQUIRE_THROWS_AS(streamIdentifier.getChannel(), std::runtime_error);
        REQUIRE_THROWS_AS(streamIdentifier.getLocationCode(), std::runtime_error);
    }
    SECTION("Set and get")
    {
        const auto streamIdentifier = makeStreamIdentifier();
        REQUIRE(streamIdentifier.hasNetwork());
        REQUIRE(streamIdentifier.hasStation());
        REQUIRE(streamIdentifier.hasChannel());
        REQUIRE(streamIdentifier.hasLocationCode());
        REQUIRE(streamIdentifier.getNetwork() == "UU");
        REQUIRE(streamIdentifier.getStation() == "CTU");
        REQUIRE(streamIdentifier.getChannel() == "HHZ");
        REQUIRE(streamIdentifier.getLocationCode() == "01");
    }
    SECTION("Empty codes throw")
    {
        StreamIdentifier streamIdentifier;
        REQUIRE_THROWS_AS(streamIdentifier.setNetwork(""), std::invalid_argument);
        REQUIRE_THROWS_AS(streamIdentifier.setStation(""), std::invalid_argument);
        REQUIRE_THROWS_AS(streamIdentifier.setChannel(""), std::invalid_argument);
    }
    SECTION("Empty location code is valid")
    {
        StreamIdentifier streamIdentifier;
        streamIdentifier.setLocationCode("");
        REQUIRE(streamIdentifier.hasLocationCode());
        REQUIRE(streamIdentifier.getLocationCode().empty());
    }
    SECTION("Copy is a deep, independent copy")
    {
        auto streamIdentifier = makeStreamIdentifier();
        const StreamIdentifier copy{streamIdentifier};
        // Mutating the source must not disturb the copy.
        streamIdentifier.setNetwork("WY");
        REQUIRE(streamIdentifier.getNetwork() == "WY");
        REQUIRE(copy.getNetwork() == "UU");
        REQUIRE(copy.getStation() == "CTU");
        REQUIRE(copy.getChannel() == "HHZ");
        REQUIRE(copy.getLocationCode() == "01");
    }
    SECTION("Move")
    {
        auto toMove = makeStreamIdentifier();
        const StreamIdentifier moved{std::move(toMove)};
        REQUIRE(moved.getNetwork() == "UU");
        REQUIRE(moved.getChannel() == "HHZ");
    }
}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::Arrival", "Arrival")
{
    SECTION("Defaults")
    {
        const Arrival arrival;
        REQUIRE_FALSE(arrival.hasIdentifier());
        REQUIRE_FALSE(arrival.hasTime());
        REQUIRE_FALSE(arrival.hasPhase());
        REQUIRE_FALSE(arrival.hasReviewStatus());
        REQUIRE_FALSE(arrival.hasStreamIdentifier());
        REQUIRE_FALSE(arrival.hasResidual());
        REQUIRE(arrival.getQuality() == std::nullopt);
        REQUIRE_THROWS_AS(arrival.getIdentifier(), std::runtime_error);
        REQUIRE_THROWS_AS(arrival.getTime(), std::runtime_error);
        REQUIRE_THROWS_AS(arrival.getPhase(), std::runtime_error);
        REQUIRE_THROWS_AS(arrival.getReviewStatus(), std::runtime_error);
        REQUIRE_THROWS_AS(arrival.getStreamIdentifier(), std::runtime_error);
        REQUIRE_THROWS_AS(arrival.getResidual(), std::runtime_error);
    }
    SECTION("Set and get")
    {
        constexpr int64_t identifier{482};
        constexpr std::chrono::nanoseconds time{1'700'000'000'123'456'789};
        constexpr std::chrono::nanoseconds residual{-25'000'000};
        constexpr double quality{0.75};

        Arrival arrival;
        arrival.setIdentifier(identifier);
        arrival.setTime(time);
        arrival.setPhase(Arrival::Phase::S);
        arrival.setReviewStatus(Arrival::ReviewStatus::Human);
        arrival.setStreamIdentifier(makeStreamIdentifier());
        arrival.setQuality(quality);
        arrival.setResidual(residual);

        REQUIRE(arrival.getIdentifier() == identifier);
        REQUIRE(arrival.getTime() == time);
        REQUIRE(arrival.getPhase() == Arrival::Phase::S);
        REQUIRE(arrival.getReviewStatus() == Arrival::ReviewStatus::Human);
        REQUIRE(arrival.hasStreamIdentifier());
        REQUIRE(arrival.getStreamIdentifier().getStation() == "CTU");
        const auto quality2 = arrival.getQuality();
        REQUIRE(quality2.has_value());
        //NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        REQUIRE(*quality2 == quality);
        REQUIRE(arrival.getResidual() == residual);
    }
    SECTION("Negative quality throws")
    {
        Arrival arrival;
        REQUIRE_THROWS_AS(arrival.setQuality(-0.1), std::invalid_argument);
        REQUIRE(arrival.getQuality() == std::nullopt);
    }
    SECTION("Incomplete stream identifier throws")
    {
        StreamIdentifier missingChannel;
        missingChannel.setNetwork("UU");
        missingChannel.setStation("CTU");
        missingChannel.setLocationCode("01");
        Arrival arrival;
        REQUIRE_THROWS_AS(arrival.setStreamIdentifier(missingChannel),
                          std::invalid_argument);
        REQUIRE_FALSE(arrival.hasStreamIdentifier());
    }
    SECTION("Copy is a deep, independent copy")
    {
        Arrival arrival;
        arrival.setIdentifier(7);
        arrival.setPhase(Arrival::Phase::P);
        arrival.setStreamIdentifier(makeStreamIdentifier());

        const Arrival copy{arrival};
        arrival.setIdentifier(8);
        REQUIRE(arrival.getIdentifier() == 8);
        REQUIRE(copy.getIdentifier() == 7);
        REQUIRE(copy.getPhase() == Arrival::Phase::P);
        REQUIRE(copy.getStreamIdentifier().getNetwork() == "UU");
    }
    SECTION("Move")
    {
        Arrival toMove;
        toMove.setIdentifier(7);
        toMove.setStreamIdentifier(makeStreamIdentifier());
        const Arrival moved{std::move(toMove)};
        REQUIRE(moved.getIdentifier() == 7);
        REQUIRE(moved.getStreamIdentifier().getChannel() == "HHZ");
    }
}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::Magnitude", "Magnitude")
{
    SECTION("Local magnitude defaults")
    {
        const LocalMagnitude magnitude;
        REQUIRE(magnitude.getType() == IMagnitude::Type::Local);
        REQUIRE(magnitude.isPreferred());
        REQUIRE_FALSE(magnitude.hasIdentifier());
        REQUIRE_FALSE(magnitude.hasValue());
        REQUIRE_FALSE(magnitude.hasReviewStatus());
        REQUIRE_THROWS_AS(magnitude.getIdentifier(), std::runtime_error);
        REQUIRE_THROWS_AS(magnitude.getValue(), std::runtime_error);
        REQUIRE_THROWS_AS(magnitude.getReviewStatus(), std::runtime_error);
    }
    SECTION("Types")
    {
        REQUIRE(LocalMagnitude{}.getType() == IMagnitude::Type::Local);
        REQUIRE(DurationMagnitude{}.getType() == IMagnitude::Type::Duration);
        REQUIRE(HumanMagnitude{}.getType() == IMagnitude::Type::Human);
    }
    SECTION("Set and get through base interface")
    {
        constexpr int64_t identifier{93};
        constexpr double value{3.4};
        LocalMagnitude magnitude;
        magnitude.setIdentifier(identifier);
        magnitude.setValue(value);
        magnitude.setReviewStatus(IMagnitude::ReviewStatus::Human);
        magnitude.setNotPreferred();

        REQUIRE(magnitude.getIdentifier() == identifier);
        REQUIRE(magnitude.getValue() == value);
        REQUIRE(magnitude.getReviewStatus() == IMagnitude::ReviewStatus::Human);
        REQUIRE_FALSE(magnitude.isPreferred());

        magnitude.setIsPreferred();
        REQUIRE(magnitude.isPreferred());
    }
    SECTION("Value bounds")
    {
        LocalMagnitude magnitude;
        REQUIRE_NOTHROW(magnitude.setValue(11.0));
        REQUIRE(magnitude.getValue() == 11.0);
        REQUIRE_NOTHROW(magnitude.setValue(-1.5));   // Small events are negative.
        REQUIRE(magnitude.getValue() == -1.5);
        REQUIRE_THROWS_AS(magnitude.setValue(11.0001), std::invalid_argument);
    }
    SECTION("Human magnitude is always human reviewed")
    {
        const HumanMagnitude magnitude;
        REQUIRE(magnitude.getReviewStatus() == IMagnitude::ReviewStatus::Human);
    }
    SECTION("Clone preserves derived type through the base pointer")
    {
        LocalMagnitude local;
        local.setIdentifier(3);
        local.setValue(4.2);
        // Hold it as a base pointer, as Event does, then clone.
        const std::unique_ptr<IMagnitude> base
            = std::make_unique<LocalMagnitude> (local);
        const auto cloned = base->clone();
        REQUIRE(cloned != nullptr);
        REQUIRE(cloned.get() != base.get());          // Distinct object.
        REQUIRE(cloned->getType() == IMagnitude::Type::Local);
        REQUIRE(cloned->getIdentifier() == 3);
        REQUIRE(cloned->getValue() == 4.2);
    }
    SECTION("Copy preserves base state and type independently")
    {
        DurationMagnitude magnitude;
        magnitude.setIdentifier(11);
        magnitude.setValue(2.1);
        magnitude.setNotPreferred();

        const DurationMagnitude copy{magnitude};
        magnitude.setValue(3.3);
        REQUIRE(magnitude.getValue() == 3.3);
        REQUIRE(copy.getType() == IMagnitude::Type::Duration);
        REQUIRE(copy.getIdentifier() == 11);
        REQUIRE(copy.getValue() == 2.1);
        REQUIRE_FALSE(copy.isPreferred());
    }
    SECTION("Move preserves base state and type")
    {
        DurationMagnitude toMove;
        toMove.setIdentifier(11);
        toMove.setValue(2.1);
        const DurationMagnitude moved{std::move(toMove)};
        REQUIRE(moved.getType() == IMagnitude::Type::Duration);
        REQUIRE(moved.getIdentifier() == 11);
        REQUIRE(moved.getValue() == 2.1);
    }
}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::Origin", "Origin")
{
    SECTION("Defaults")
    {
        const Origin origin;
        REQUIRE(origin.isPreferred());
        REQUIRE(origin.getArrivals().empty());
        REQUIRE_FALSE(origin.hasIdentifier());
        REQUIRE_FALSE(origin.hasLatitude());
        REQUIRE_FALSE(origin.hasLongitude());
        REQUIRE_FALSE(origin.hasDepth());
        REQUIRE_FALSE(origin.hasTime());
        REQUIRE_FALSE(origin.hasGeographicType());
        REQUIRE_FALSE(origin.hasReviewStatus());
        REQUIRE_THROWS_AS(origin.getIdentifier(), std::runtime_error);
        REQUIRE_THROWS_AS(origin.getLatitude(), std::runtime_error);
        REQUIRE_THROWS_AS(origin.getLongitude(), std::runtime_error);
        REQUIRE_THROWS_AS(origin.getDepth(), std::runtime_error);
        REQUIRE_THROWS_AS(origin.getTime(), std::runtime_error);
        REQUIRE_THROWS_AS(origin.getGeographicType(), std::runtime_error);
        REQUIRE_THROWS_AS(origin.getReviewStatus(), std::runtime_error);
    }
    SECTION("Set and get")
    {
        constexpr std::chrono::nanoseconds time{1'700'000'000'000'000'000};
        Origin origin;
        origin.setIdentifier(55);
        origin.setLatitude(40.77);
        origin.setDepth(5000);
        origin.setTime(time);
        origin.setGeographicType(Origin::GeographicType::Local);
        origin.setReviewStatus(Origin::ReviewStatus::Finalized);
        origin.setNotPreferred();

        REQUIRE(origin.getIdentifier() == 55);
        REQUIRE(origin.getLatitude() == 40.77);
        REQUIRE(origin.getDepth() == 5000);
        REQUIRE(origin.getTime() == time);
        REQUIRE(origin.getGeographicType() == Origin::GeographicType::Local);
        REQUIRE(origin.getReviewStatus() == Origin::ReviewStatus::Finalized);
        REQUIRE_FALSE(origin.isPreferred());
    }
    SECTION("Latitude bounds")
    {
        Origin origin;
        REQUIRE_NOTHROW(origin.setLatitude(-90.0));
        REQUIRE_NOTHROW(origin.setLatitude(90.0));
        REQUIRE_THROWS_AS(origin.setLatitude(-90.001), std::invalid_argument);
        REQUIRE_THROWS_AS(origin.setLatitude(90.001), std::invalid_argument);
    }
    SECTION("Depth bounds")
    {
        Origin origin;
        REQUIRE_NOTHROW(origin.setDepth(-8600.0));
        REQUIRE_NOTHROW(origin.setDepth(800000.0));
        REQUIRE_THROWS_AS(origin.setDepth(-8600.1), std::invalid_argument);
        REQUIRE_THROWS_AS(origin.setDepth(800000.1), std::invalid_argument);
    }
    SECTION("Longitude is normalized to [0, 360)")
    {
        Origin origin;
        origin.setLongitude(-111.89);
        REQUIRE(origin.getLongitude() == Catch::Approx(248.11));

        origin.setLongitude(370.0);
        REQUIRE(origin.getLongitude() == Catch::Approx(10.0));

        origin.setLongitude(360.0);
        REQUIRE(origin.getLongitude() == Catch::Approx(0.0));

        origin.setLongitude(180.0);
        REQUIRE(origin.getLongitude() == Catch::Approx(180.0));
    }
    SECTION("Arrivals round trip")
    {
        Arrival arrival1;
        arrival1.setIdentifier(1);
        arrival1.setPhase(Arrival::Phase::P);
        arrival1.setStreamIdentifier(makeStreamIdentifier());
        arrival1.setTime(std::chrono::seconds {1784745696});
        arrival1.setReviewStatus(Arrival::ReviewStatus::Automatic);

        Arrival arrival2;
        arrival2.setIdentifier(2);
        arrival2.setPhase(Arrival::Phase::S);
        arrival2.setStreamIdentifier(makeStreamIdentifier());
        arrival2.setTime(std::chrono::seconds {1784745697});
        arrival2.setReviewStatus(Arrival::ReviewStatus::Human);

        Origin origin;
        origin.setArrivals(std::vector<Arrival> {arrival1, arrival2});
        const auto arrivals = origin.getArrivals();
        REQUIRE(arrivals.size() == 2);
        REQUIRE(arrivals.at(0).getIdentifier() == 1);
        REQUIRE(arrivals.at(1).getStreamIdentifier().getStation() == "CTU");
        REQUIRE(arrivals.at(1).getIdentifier() == 2);
    }
    SECTION("Copy is a deep, independent copy")
    {
        auto origin = makeValidOrigin();
        origin.setIdentifier(9);
        origin.setNotPreferred();

        const Origin copy{origin};
        origin.setIdentifier(10);
        REQUIRE(origin.getIdentifier() == 10);
        REQUIRE(copy.getIdentifier() == 9);
        REQUIRE(copy.getLatitude() == 40.77);
        REQUIRE_FALSE(copy.isPreferred());
    }
    SECTION("Move")
    {
        auto toMove = makeValidOrigin();
        toMove.setIdentifier(9);
        const Origin moved{std::move(toMove)};
        REQUIRE(moved.getIdentifier() == 9);
        REQUIRE(moved.hasDepth());
    }
}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::Event", "Event")
{
    SECTION("Defaults")
    {
        const Event event;
        REQUIRE_FALSE(event.hasIdentifier());
        REQUIRE_FALSE(event.hasOrigins());
        REQUIRE_FALSE(event.hasMagnitudes());
        REQUIRE_FALSE(event.hasEventType());
        REQUIRE_THROWS_AS(event.getIdentifier(), std::runtime_error);
        REQUIRE_THROWS_AS(event.getEventType(), std::runtime_error);
        REQUIRE_THROWS_AS(event.getOrigins(), std::runtime_error);
        REQUIRE_THROWS_AS(event.getPreferredOrigin(), std::runtime_error);
        REQUIRE_THROWS_AS(event.getMagnitudes(), std::runtime_error);
        REQUIRE_THROWS_AS(event.getPreferredMagnitude(), std::runtime_error);
    }
    SECTION("Set and get")
    {
        Event event;
        event.setIdentifier(2024);
        event.setEventType(Event::EventType::Earthquake);
        event.setOrigins(std::vector<Origin> {makeValidOrigin()});

        REQUIRE(event.getIdentifier() == 2024);
        REQUIRE(event.getEventType() == Event::EventType::Earthquake);
        REQUIRE(event.hasOrigins());
        REQUIRE(event.getOrigins().size() == 1);
    }
    SECTION("Empty origins throw")
    {
        Event event;
        REQUIRE_THROWS_AS(event.setOrigins(std::vector<Origin> {}),
                          std::invalid_argument);
    }
    SECTION("Origins missing required fields throw")
    {
        Origin noLatitude;
        noLatitude.setLongitude(-111.89);
        noLatitude.setDepth(5000);
        noLatitude.setTime(std::chrono::nanoseconds{1});

        Origin noTime;
        noTime.setLatitude(40.77);
        noTime.setLongitude(-111.89);
        noTime.setDepth(5000);

        Event event;
        REQUIRE_THROWS_AS(event.setOrigins(std::vector<Origin> {noLatitude}),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(event.setOrigins(std::vector<Origin> {noTime}),
                          std::invalid_argument);
    }
    SECTION("Exactly one preferred origin is required")
    {
        Event event;

        auto nonePreferred = makeValidOrigin();
        nonePreferred.setNotPreferred();
        REQUIRE_THROWS_AS(event.setOrigins(std::vector<Origin> {nonePreferred}),
                          std::invalid_argument);

        auto first = makeValidOrigin(10.0, 20.0, 1000);
        first.setIsPreferred();
        auto second = makeValidOrigin(40.77, -111.89, 5000);
        second.setIsPreferred();
        REQUIRE_THROWS_AS(event.setOrigins(std::vector<Origin> {first, second}),
                          std::invalid_argument);
    }
    SECTION("Preferred origin is selected")
    {
        auto notPreferred = makeValidOrigin(10.0, 20.0, 1000);
        notPreferred.setIdentifier(1);
        notPreferred.setNotPreferred();

        auto preferred = makeValidOrigin(40.77, -111.89, 5000);
        preferred.setIdentifier(2);
        preferred.setIsPreferred();

        Event event;
        event.setOrigins(std::vector<Origin> {notPreferred, preferred});
        REQUIRE(event.getOrigins().size() == 2);
        REQUIRE(event.getPreferredOrigin().getIdentifier() == 2);
    }
    SECTION("Magnitudes round trip and preserve derived types")
    {
        Event event;
        event.setMagnitudes(makeMagnitudes());
        REQUIRE(event.hasMagnitudes());

        const auto magnitudes = event.getMagnitudes();
        REQUIRE(magnitudes.size() == 2);
        // clone() must have preserved the concrete subclass of each element.
        REQUIRE(magnitudes.at(0)->getType() == IMagnitude::Type::Local);
        REQUIRE(magnitudes.at(0)->getValue() == 3.4);
        REQUIRE(magnitudes.at(0)->isPreferred());
        REQUIRE(magnitudes.at(1)->getType() == IMagnitude::Type::Duration);
        REQUIRE(magnitudes.at(1)->getValue() == 3.1);
        REQUIRE_FALSE(magnitudes.at(1)->isPreferred());

        const auto preferred = event.getPreferredMagnitude();
        REQUIRE(preferred->getType() == IMagnitude::Type::Local);
        REQUIRE(preferred->getValue() == 3.4);
    }
    SECTION("Empty magnitudes throw")
    {
        Event event;
        REQUIRE_THROWS_AS(
            event.setMagnitudes(std::vector<std::unique_ptr<IMagnitude>> {}),
            std::invalid_argument);
    }
    SECTION("Null magnitude throws")
    {
        std::vector<std::unique_ptr<IMagnitude>> magnitudes;
        magnitudes.push_back(std::make_unique<LocalMagnitude> ());
        magnitudes.push_back(nullptr);
        Event event;
        REQUIRE_THROWS_AS(event.setMagnitudes(magnitudes),
                          std::invalid_argument);
    }
    SECTION("Duplicate magnitude types throw")
    {
        auto first = std::make_unique<LocalMagnitude> ();
        first->setIsPreferred();
        auto second = std::make_unique<LocalMagnitude> ();
        second->setNotPreferred();
        std::vector<std::unique_ptr<IMagnitude>> magnitudes;
        magnitudes.push_back(std::move(first));
        magnitudes.push_back(std::move(second));
        Event event;
        REQUIRE_THROWS_AS(event.setMagnitudes(magnitudes),
                          std::invalid_argument);
    }
    SECTION("Exactly one preferred magnitude is required")
    {
        Event event;

        std::vector<std::unique_ptr<IMagnitude>> nonePreferred;
        auto local = std::make_unique<LocalMagnitude> ();
        local->setNotPreferred();
        nonePreferred.push_back(std::move(local));
        REQUIRE_THROWS_AS(event.setMagnitudes(nonePreferred),
                          std::invalid_argument);

        std::vector<std::unique_ptr<IMagnitude>> twoPreferred;
        auto localPref = std::make_unique<LocalMagnitude> ();
        localPref->setIsPreferred();
        auto durationPref = std::make_unique<DurationMagnitude> ();
        durationPref->setIsPreferred();
        twoPreferred.push_back(std::move(localPref));
        twoPreferred.push_back(std::move(durationPref));
        REQUIRE_THROWS_AS(event.setMagnitudes(twoPreferred),
                          std::invalid_argument);
    }
    SECTION("Copy is a deep, independent copy")
    {
        Event event;
        event.setIdentifier(2024);
        event.setEventType(Event::EventType::QuarryBlast);
        event.setOrigins(std::vector<Origin> {makeValidOrigin()});
        event.setMagnitudes(makeMagnitudes());

        const Event copy{event};
        event.setIdentifier(2025);
        REQUIRE(event.getIdentifier() == 2025);
        REQUIRE(copy.getIdentifier() == 2024);
        REQUIRE(copy.getEventType() == Event::EventType::QuarryBlast);
        REQUIRE(copy.getOrigins().size() == 1);
        // The polymorphic magnitudes must survive the deep copy intact.
        REQUIRE(copy.getMagnitudes().size() == 2);
        REQUIRE(copy.getPreferredMagnitude()->getType()
                == IMagnitude::Type::Local);
    }
    SECTION("Move")
    {
        Event toMove;
        toMove.setIdentifier(2024);
        toMove.setOrigins(std::vector<Origin> {makeValidOrigin()});
        toMove.setMagnitudes(makeMagnitudes());
        const Event moved{std::move(toMove)};
        REQUIRE(moved.getIdentifier() == 2024);
        REQUIRE(moved.getPreferredOrigin().hasLatitude());
        REQUIRE(moved.getMagnitudes().size() == 2);
        REQUIRE(moved.getPreferredMagnitude()->getType()
                == IMagnitude::Type::Local);
    }
}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::PeakToPeakAmplitude",
          "PeakToPeakAmplitude")
{
    SECTION("Defaults")
    {
        const PeakToPeakAmplitude amplitude;
        REQUIRE_FALSE(amplitude.hasStreamIdentifier());
        REQUIRE_FALSE(amplitude.hasPeakTimes());
        REQUIRE_FALSE(amplitude.hasAmplitude());
        REQUIRE_THROWS_AS(amplitude.getStreamIdentifier(), std::runtime_error);
        REQUIRE_THROWS_AS(amplitude.getPeakTimes(), std::runtime_error);
        REQUIRE_THROWS_AS(amplitude.getAmplitude(), std::runtime_error);
    }
    SECTION("Amplitude is normalized to millimeters")
    {
        PeakToPeakAmplitude amplitude;
        amplitude.setAmplitude(2.0, PeakToPeakAmplitude::Units::Meters);
        REQUIRE(amplitude.getAmplitude() == Catch::Approx(2000.0));
        amplitude.setAmplitude(2.0, PeakToPeakAmplitude::Units::Centimeters);
        REQUIRE(amplitude.getAmplitude() == Catch::Approx(20.0));
        amplitude.setAmplitude(2.0, PeakToPeakAmplitude::Units::Millimeters);
        REQUIRE(amplitude.getAmplitude() == Catch::Approx(2.0));
    }
    SECTION("Non-positive amplitude throws")
    {
        PeakToPeakAmplitude amplitude;
        REQUIRE_THROWS_AS(
            amplitude.setAmplitude(0.0, PeakToPeakAmplitude::Units::Millimeters),
            std::invalid_argument);
        REQUIRE_THROWS_AS(
            amplitude.setAmplitude(-1.0, PeakToPeakAmplitude::Units::Meters),
            std::invalid_argument);
        REQUIRE_FALSE(amplitude.hasAmplitude());
    }
    SECTION("Stream identifier and peak times round trip")
    {
        constexpr std::chrono::nanoseconds firstPeak{100};
        constexpr std::chrono::nanoseconds secondPeak{250};
        PeakToPeakAmplitude amplitude;
        amplitude.setStreamIdentifier(makeStream("HHN"));
        const std::pair<std::chrono::nanoseconds, std::chrono::nanoseconds>
            peakTimes{firstPeak, secondPeak};
        amplitude.setPeakTimes(peakTimes);

        REQUIRE(amplitude.hasStreamIdentifier());
        REQUIRE(amplitude.getStreamIdentifier().getChannel() == "HHN");
        REQUIRE(amplitude.hasPeakTimes());
        REQUIRE(amplitude.getPeakTimes().first == firstPeak);
        REQUIRE(amplitude.getPeakTimes().second == secondPeak);
    }
    SECTION("Copy is a deep, independent copy")
    {
        auto amplitude = makeAmplitude("HHN", 6.434);
        const PeakToPeakAmplitude copy{amplitude};
        amplitude.setAmplitude(1.0, PeakToPeakAmplitude::Units::Millimeters);
        REQUIRE(copy.getAmplitude() == Catch::Approx(6.434));
        REQUIRE(copy.getStreamIdentifier().getChannel() == "HHN");
    }
    SECTION("Move")
    {
        auto toMove = makeAmplitude("HHE", 3.180);
        const PeakToPeakAmplitude moved{std::move(toMove)};
        REQUIRE(moved.getAmplitude() == Catch::Approx(3.180));
        REQUIRE(moved.getStreamIdentifier().getChannel() == "HHE");
    }
}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::StationLocalMagnitude",
          "StationLocalMagnitude")
{
    SECTION("Defaults")
    {
        const StationLocalMagnitude magnitude;
        REQUIRE_FALSE(magnitude.hasPeakToPeakAmplitudes());
        REQUIRE_FALSE(magnitude.hasWeight());
        REQUIRE_THROWS_AS(magnitude.getPeakToPeakAmplitudes(),
                          std::runtime_error);
        REQUIRE_THROWS_AS(magnitude.getWeight(), std::runtime_error);
    }
    SECTION("A valid two-channel amplitude pair round trips")
    {
        StationLocalMagnitude magnitude;
        magnitude.setPeakToPeakAmplitudes(
            {makeAmplitude("HHN", 6.434), makeAmplitude("HHE", 3.180)});
        REQUIRE(magnitude.hasPeakToPeakAmplitudes());
        const auto amplitudes = magnitude.getPeakToPeakAmplitudes();
        REQUIRE(amplitudes.first.getStreamIdentifier().getChannel() == "HHN");
        REQUIRE(amplitudes.second.getStreamIdentifier().getChannel() == "HHE");
    }
    SECTION("Two amplitudes from the same stream are rejected")
    {
        StationLocalMagnitude magnitude;
        REQUIRE_THROWS_AS(
            magnitude.setPeakToPeakAmplitudes(
                {makeAmplitude("HHN", 6.434), makeAmplitude("HHN", 3.180)}),
            std::invalid_argument);
    }
    SECTION("Amplitudes missing required fields are rejected")
    {
        StationLocalMagnitude magnitude;

        PeakToPeakAmplitude noStream;
        noStream.setAmplitude(1.0, PeakToPeakAmplitude::Units::Millimeters);
        REQUIRE_THROWS_AS(
            magnitude.setPeakToPeakAmplitudes(
                {noStream, makeAmplitude("HHE", 3.180)}),
            std::invalid_argument);

        PeakToPeakAmplitude noPeakTimes;
        noPeakTimes.setStreamIdentifier(makeStream("HHN"));
        noPeakTimes.setAmplitude(1.0, PeakToPeakAmplitude::Units::Millimeters);
        REQUIRE_THROWS_AS(
            magnitude.setPeakToPeakAmplitudes(
                {noPeakTimes, makeAmplitude("HHE", 3.180)}),
            std::invalid_argument);

        PeakToPeakAmplitude noAmplitude;
        noAmplitude.setStreamIdentifier(makeStream("HHN"));
        const std::pair<std::chrono::nanoseconds, std::chrono::nanoseconds>
            peakTimes{std::chrono::nanoseconds{1}, std::chrono::nanoseconds{2}};
        noAmplitude.setPeakTimes(peakTimes);
        REQUIRE_THROWS_AS(
            magnitude.setPeakToPeakAmplitudes(
                {noAmplitude, makeAmplitude("HHE", 3.180)}),
            std::invalid_argument);
    }
    SECTION("Weight bounds")
    {
        StationLocalMagnitude magnitude;
        REQUIRE_THROWS_AS(magnitude.setWeight(-0.1), std::invalid_argument);
        REQUIRE_THROWS_AS(magnitude.setWeight(1.1), std::invalid_argument);
        REQUIRE_NOTHROW(magnitude.setWeight(0.0));
        REQUIRE_NOTHROW(magnitude.setWeight(1.0));
        REQUIRE(magnitude.getWeight() == 1.0);
    }
    SECTION("Copy is a deep, independent copy")
    {
        StationLocalMagnitude magnitude;
        magnitude.setPeakToPeakAmplitudes(
            {makeAmplitude("HHN", 6.434), makeAmplitude("HHE", 3.180)});
        magnitude.setWeight(1.0);

        const StationLocalMagnitude copy{magnitude};
        magnitude.setWeight(0.0);
        REQUIRE(magnitude.getWeight() == 0.0);
        REQUIRE(copy.getWeight() == 1.0);
        REQUIRE(copy.hasPeakToPeakAmplitudes());
    }
}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::StationDurationMagnitude",
          "StationDurationMagnitude")
{
    SECTION("Defaults")
    {
        const StationDurationMagnitude magnitude;
        REQUIRE_FALSE(magnitude.hasDuration());
        REQUIRE_FALSE(magnitude.hasDistance());
        REQUIRE_FALSE(magnitude.hasResidual());
        REQUIRE_FALSE(magnitude.hasWeight());
        REQUIRE(magnitude.getCorrection() == 0.0);   // Default, not "has".
        REQUIRE(magnitude.getDistance() == 0.0);      // noexcept: 0 when unset.
        REQUIRE_THROWS_AS(magnitude.getDuration(), std::runtime_error);
        REQUIRE_THROWS_AS(magnitude.getResidual(), std::runtime_error);
        REQUIRE_THROWS_AS(magnitude.getWeight(), std::runtime_error);
    }
    SECTION("Duration must be positive")
    {
        StationDurationMagnitude magnitude;
        REQUIRE_THROWS_AS(magnitude.setDuration(0.0), std::invalid_argument);
        REQUIRE_THROWS_AS(magnitude.setDuration(-1.0), std::invalid_argument);
        magnitude.setDuration(12.5);
        REQUIRE(magnitude.hasDuration());
        REQUIRE(magnitude.getDuration() == 12.5);
    }
    SECTION("Distance cannot be negative")
    {
        StationDurationMagnitude magnitude;
        REQUIRE_THROWS_AS(magnitude.setDistance(-1.0), std::invalid_argument);
        magnitude.setDistance(177000.0);
        REQUIRE(magnitude.hasDistance());
        REQUIRE(magnitude.getDistance() == 177000.0);
    }
    SECTION("Correction and residual")
    {
        StationDurationMagnitude magnitude;
        magnitude.setCorrection(-0.55);
        REQUIRE(magnitude.getCorrection() == -0.55);
        magnitude.setResidual(0.22);
        REQUIRE(magnitude.hasResidual());
        REQUIRE(magnitude.getResidual() == 0.22);
    }
    SECTION("Weight bounds")
    {
        StationDurationMagnitude magnitude;
        REQUIRE_THROWS_AS(magnitude.setWeight(-0.1), std::invalid_argument);
        REQUIRE_THROWS_AS(magnitude.setWeight(1.1), std::invalid_argument);
        REQUIRE_NOTHROW(magnitude.setWeight(1.0));
        REQUIRE(magnitude.getWeight() == 1.0);
    }
    SECTION("Copy is a deep, independent copy")
    {
        StationDurationMagnitude magnitude;
        magnitude.setDuration(12.5);
        magnitude.setDistance(177000.0);

        const StationDurationMagnitude copy{magnitude};
        magnitude.setDuration(20.0);
        REQUIRE(magnitude.getDuration() == 20.0);
        REQUIRE(copy.getDuration() == 12.5);
        REQUIRE(copy.getDistance() == 177000.0);
    }
}

TEST_CASE("UEventAnalysisToolBackend::Database::AQMS::NetworkMagnitudeStations",
          "NetworkMagnitudeStations")
{
    SECTION("LocalMagnitude aggregates station magnitudes")
    {
        StationLocalMagnitude station;
        station.setPeakToPeakAmplitudes(
            {makeAmplitude("HHN", 6.434), makeAmplitude("HHE", 3.180)});
        station.setWeight(1.0);

        LocalMagnitude magnitude;
        magnitude.setValue(3.23);
        magnitude.setStationMagnitudes(
            std::vector<StationLocalMagnitude> {station, station});
        REQUIRE(magnitude.getStationMagnitudes().size() == 2);
        REQUIRE(magnitude.getStationMagnitudes().at(0).getWeight() == 1.0);
        // The base magnitude value is untouched by the station list.
        REQUIRE(magnitude.getValue() == 3.23);
    }
    SECTION("LocalMagnitude station magnitudes can be moved in")
    {
        StationLocalMagnitude station;
        station.setPeakToPeakAmplitudes(
            {makeAmplitude("HHN", 6.434), makeAmplitude("HHE", 3.180)});
        std::vector<StationLocalMagnitude> stations{station, station, station};

        LocalMagnitude magnitude;
        magnitude.setStationMagnitudes(std::move(stations));
        REQUIRE(magnitude.getStationMagnitudes().size() == 3);
    }
    SECTION("DurationMagnitude aggregates station magnitudes")
    {
        StationDurationMagnitude station;
        station.setDuration(12.5);
        station.setDistance(177000.0);

        DurationMagnitude magnitude;
        magnitude.setValue(2.9);
        magnitude.setStationMagnitudes(
            std::vector<StationDurationMagnitude> {station, station});
        REQUIRE(magnitude.getStationMagnitudes().size() == 2);
        REQUIRE(magnitude.getStationMagnitudes().at(1).getDuration() == 12.5);
        REQUIRE(magnitude.getValue() == 2.9);
    }
}
