#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "uEventAnalysisToolBackend/database/aqms/origin.hpp"
#include "uEventAnalysisToolBackend/database/aqms/arrival.hpp"
#include "uEventAnalysisToolBackend/database/aqms/streamIdentifier.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

namespace
{
constexpr double minimumLatitude{-90};
constexpr double maximumLatitude{90};
constexpr double minimumDepth{-8600};
constexpr double maximumDepth{800000};
}

class Origin::OriginImpl
{
public:
    std::vector<Arrival> mArrivals;
    std::chrono::nanoseconds mTime{0};
    int64_t mIdentifier{0};
    double mLatitude{0};
    double mLongitude{0};
    double mDepth{0};
    GeographicType mGeographicType{GeographicType::Local};
    ReviewStatus mReviewStatus{ReviewStatus::Automatic};
    bool mHasIdentifier{false};
    bool mHasLatitude{false};
    bool mHasLongitude{false};
    bool mHasDepth{false};
    bool mHasTime{false};
    bool mHasGeographicType{false};
    bool mHasReviewStatus{false};
    bool mPreferred{true};
};

/// Constructor
Origin::Origin() :
    pImpl(std::make_unique<OriginImpl> ())
{
}

/// Copy constructor
Origin::Origin(const Origin &origin)
{
    *this = origin;
}

/// Move constructor
Origin::Origin(Origin &&origin) noexcept
{
    *this = std::move(origin);
}

/// Copy assignment
Origin& Origin::operator=(const Origin &origin)
{
    if (&origin == this){return *this;}
    pImpl = std::make_unique<OriginImpl> (*origin.pImpl);
    return *this;
}

/// Move assignment
Origin& Origin::operator=(Origin &&origin) noexcept
{
    if (&origin == this){return *this;}
    pImpl = std::move(origin.pImpl);
    return *this;
}

/// Destructor
Origin::~Origin() = default;

/// Identifier
void Origin::setIdentifier(const int64_t identifier)
{
    pImpl->mIdentifier = identifier;
    pImpl->mHasIdentifier = true;
}

int64_t Origin::getIdentifier() const
{
    if (!hasIdentifier()){throw std::runtime_error("Origin identifier not set");}
    return pImpl->mIdentifier;
}

bool Origin::hasIdentifier() const noexcept
{
    return pImpl->mHasIdentifier;
}

/// Latitude
void Origin::setLatitude(const double latitude)
{
    if (latitude < minimumLatitude || latitude > maximumLatitude)
    {
        throw std::invalid_argument("Latitude must be in range ["
                                  + std::to_string(minimumLatitude) + ","
                                  + std::to_string(maximumLatitude) + "]");
    }
    pImpl->mLatitude = latitude;
    pImpl->mHasLatitude = true;
}

double Origin::getLatitude() const
{
    if (!hasLatitude()){throw std::runtime_error("Latitude not set");}
    return pImpl->mLatitude;
}

bool Origin::hasLatitude() const noexcept
{
    return pImpl->mHasLatitude;
}

/// Longitude
void Origin::setLongitude(const double longitude)
{
    auto lon = std::fmod(longitude, 360.0);
    if (lon < 0){lon = lon + 360.0;}
    pImpl->mLongitude = lon;
    pImpl->mHasLongitude = true;
}

double Origin::getLongitude() const
{
    if (!hasLongitude()){throw std::runtime_error("Longitude not set");}
    return pImpl->mLongitude;
}

bool Origin::hasLongitude() const noexcept
{
    return pImpl->mHasLongitude;
}

/// Depth
void Origin::setDepth(const double depth)
{
    if (depth < minimumDepth || depth > maximumDepth)
    {
        throw std::invalid_argument("Depth must be in range ["
                                  + std::to_string(minimumDepth) + ","
                                  + std::to_string(maximumDepth) + "] meters");
    }
    pImpl->mDepth = depth;
    pImpl->mHasDepth = true;
}

double Origin::getDepth() const
{
    if (!hasDepth()){throw std::runtime_error("Depth not set");}
    return pImpl->mDepth;
}

bool Origin::hasDepth() const noexcept
{
    return pImpl->mHasDepth;
}

/// Time
void Origin::setTime(const std::chrono::nanoseconds &time)
{
    pImpl->mTime = time;
    pImpl->mHasTime = true;
}

std::chrono::nanoseconds Origin::getTime() const
{
    if (!hasTime()){throw std::runtime_error("Origin time not set");}
    return pImpl->mTime;
}

bool Origin::hasTime() const noexcept
{
    return pImpl->mHasTime;
}

/// Arrivals
void Origin::setArrivals(const std::vector<Arrival> &arrivals)
{
    auto copy = arrivals;
    setArrivals(std::move(copy));
}

void Origin::setArrivals(std::vector<Arrival> &&arrivals)
{
    if (arrivals.empty())
    {
        throw std::invalid_argument("No arrivals");
    }
    for (const auto &arrival : arrivals)
    {
        if (!arrival.hasTime())
        {
            throw std::invalid_argument("Arrival time not set");
        }
        if (!arrival.hasStreamIdentifier())
        {
            throw std::invalid_argument("Arrival stream not set");
        }
        if (!arrival.hasPhase())
        {
            throw std::invalid_argument("Arrival phase not set");
        }
        if (!arrival.hasReviewStatus())
        {
            throw std::invalid_argument("Review status not set");
        }
    }
    std::sort(arrivals.begin(), arrivals.end(), 
              [](const auto &lhs, const auto &rhs)
              {
                  return lhs.getTime() < rhs.getTime();
              });
    auto nArrivals = static_cast<int> (arrivals.size());
    for (int i = 0; i < nArrivals; ++i)
    {
        const auto sid1 = arrivals[i].getStreamIdentifier();
        auto iPhase = arrivals[i].getPhase();
        for (int j = i + 1; j < nArrivals; ++j)
        {
            auto sid2 = arrivals[j].getStreamIdentifier();
            if (sid1.getNetwork() == sid2.getNetwork() &&
                sid1.getStation() == sid2.getStation() &&
                sid1.getChannel() == sid2.getChannel() &&
                sid1.getLocationCode() == sid2.getLocationCode())
            {
                auto jPhase = arrivals[j].getPhase();
                if (iPhase == jPhase)
                {
                    std::string sPhase1 = (iPhase == Arrival::Phase::P) ? "P" : "S"; 
                    auto nscl1 = sid1.getNetwork()
                               + "."
                               + sid1.getStation()
                               + "."
                               + sid1.getChannel()
                               + "."
                               + sid1.getLocationCode()
                               + " " 
                               + sPhase1;
                    std::string sPhase2 = (jPhase == Arrival::Phase::P) ? "P" : "S";
                    auto nscl2 = sid2.getNetwork()
                               + "."
                               + sid2.getStation()
                               + "."
                               + sid2.getChannel()
                               + "."
                               + sid2.getLocationCode()
                               + " " 
                               + sPhase2;
                    throw std::invalid_argument("Duplicate arrival "
                        + nscl1 + " " + nscl2);
                }
                if (iPhase == Arrival::Phase::P &&
                    jPhase == Arrival::Phase::S)
                {
                    if (arrivals[i].getTime() > arrivals[j].getTime())
                    {
                        throw std::invalid_argument("P after S");
                    }
                }
                if (iPhase == Arrival::Phase::S &&
                    jPhase == Arrival::Phase::P)
                {
                    if (arrivals[i].getTime() < arrivals[j].getTime())
                    {
                        throw std::invalid_argument("S before P");
                    }
                } 
            }
        }
    }
    pImpl->mArrivals = arrivals;
}

std::vector<Arrival> Origin::getArrivals() const noexcept
{
    return pImpl->mArrivals;
}

/// Geographic type
void Origin::setGeographicType(const GeographicType type) noexcept
{
    pImpl->mGeographicType = type;
    pImpl->mHasGeographicType = true;
}

Origin::GeographicType Origin::getGeographicType() const
{
    if (!hasGeographicType())
    {
        throw std::runtime_error("Geographic type not set");
    }
    return pImpl->mGeographicType;
}

bool Origin::hasGeographicType() const noexcept
{
    return pImpl->mHasGeographicType;
}

/// Review status
void Origin::setReviewStatus(const ReviewStatus status) noexcept
{
    pImpl->mReviewStatus = status;
    pImpl->mHasReviewStatus = true;
}

Origin::ReviewStatus Origin::getReviewStatus() const
{
    if (!hasReviewStatus()){throw std::runtime_error("Review status not set");}
    return pImpl->mReviewStatus;
}

bool Origin::hasReviewStatus() const noexcept
{
    return pImpl->mHasReviewStatus;
}

/// Preferred
void Origin::setIsPreferred() noexcept
{
    pImpl->mPreferred = true;
}

void Origin::setNotPreferred() noexcept
{
    pImpl->mPreferred = false;
}

bool Origin::isPreferred() const noexcept
{
    return pImpl->mPreferred;
}
