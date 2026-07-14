#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include "uEventAnalysisToolBackend/database/aqms/arrival.hpp"
#include "uEventAnalysisToolBackend/database/aqms/streamIdentifier.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

class Arrival::ArrivalImpl
{
public:
    StreamIdentifier mStreamIdentifier;
    std::optional<double> mQuality;
    std::chrono::nanoseconds mTime{0};
    std::chrono::nanoseconds mResidual{0};
    int64_t mIdentifier{0};
    Phase mPhase{Phase::P};
    ReviewStatus mReviewStatus{ReviewStatus::Automatic};
    bool mHasIdentifier{false};
    bool mHasTime{false};
    bool mHasPhase{false};
    bool mHasReviewStatus{false};
    bool mHasStreamIdentifier{false};
    bool mHasResidual{false};
};

/// Constructor
Arrival::Arrival() :
    pImpl(std::make_unique<ArrivalImpl> ())
{
}

/// Copy constructor
Arrival::Arrival(const Arrival &arrival)
{
    *this = arrival;
}

/// Move constructor
Arrival::Arrival(Arrival &&arrival) noexcept
{
    *this = std::move(arrival);
}

/// Copy assignment
Arrival& Arrival::operator=(const Arrival &arrival)
{
    if (&arrival == this){return *this;}
    pImpl = std::make_unique<ArrivalImpl> (*arrival.pImpl);
    return *this;
}

/// Move assignment
Arrival& Arrival::operator=(Arrival &&arrival) noexcept
{
    if (&arrival == this){return *this;}
    pImpl = std::move(arrival.pImpl);
    return *this;
}

/// Destructor
Arrival::~Arrival() = default;

/// Identifier
void Arrival::setIdentifier(const int64_t identifier)
{
    pImpl->mIdentifier = identifier;
    pImpl->mHasIdentifier = true;
}

int64_t Arrival::getIdentifier() const
{
    if (!hasIdentifier()){throw std::runtime_error("Arrival identifier not set");}
    return pImpl->mIdentifier;
}

bool Arrival::hasIdentifier() const noexcept
{
    return pImpl->mHasIdentifier;
}

/// Time
void Arrival::setTime(const std::chrono::nanoseconds &time) noexcept
{
    pImpl->mTime = time;
    pImpl->mHasTime = true;
}

std::chrono::nanoseconds Arrival::getTime() const
{
    if (!hasTime()){throw std::runtime_error("Arrival time not set");}
    return pImpl->mTime;
}

bool Arrival::hasTime() const noexcept
{
    return pImpl->mHasTime;
}

/// Phase
void Arrival::setPhase(const Phase phase) noexcept
{
    pImpl->mPhase = phase;
    pImpl->mHasPhase = true;
}

Arrival::Phase Arrival::getPhase() const
{
    if (!hasPhase()){throw std::runtime_error("Phase not set");}
    return pImpl->mPhase;
}

bool Arrival::hasPhase() const noexcept
{
    return pImpl->mHasPhase;
}

/// Review status
void Arrival::setReviewStatus(const ReviewStatus status) noexcept
{
    pImpl->mReviewStatus = status;
    pImpl->mHasReviewStatus = true;
}

Arrival::ReviewStatus Arrival::getReviewStatus() const
{
    if (!hasReviewStatus()){throw std::runtime_error("Review status not set");}
    return pImpl->mReviewStatus;
}

bool Arrival::hasReviewStatus() const noexcept
{
    return pImpl->mHasReviewStatus;
}

/// Stream identifier
void Arrival::setStreamIdentifier(const StreamIdentifier &identifier)
{
    if (!identifier.hasNetwork())
    {
        throw std::invalid_argument("Network not set on stream identifier");
    }
    if (!identifier.hasStation())
    {
        throw std::invalid_argument("Station not set on stream identifier");
    }
    if (!identifier.hasChannel())
    {
        throw std::invalid_argument("Channel not set on stream identifier");
    }
    if (!identifier.hasLocationCode())
    {
        throw std::invalid_argument("Location code not set on stream identifier");
    }
    pImpl->mStreamIdentifier = identifier;
    pImpl->mHasStreamIdentifier = true;
}

StreamIdentifier Arrival::getStreamIdentifier() const
{
    if (!hasStreamIdentifier())
    {
        throw std::runtime_error("Stream identifier not set");
    }
    return pImpl->mStreamIdentifier;
}

bool Arrival::hasStreamIdentifier() const noexcept
{
    return pImpl->mHasStreamIdentifier;
}

/// Quality
void Arrival::setQuality(const double quality)
{
    if (quality < 0)
    {
        throw std::invalid_argument("Quality cannot be negative");
    }
    pImpl->mQuality = quality;
}

std::optional<double> Arrival::getQuality() const noexcept
{
    return pImpl->mQuality;
}

/// Residual
void Arrival::setResidual(const std::chrono::nanoseconds &residual)
{
    pImpl->mResidual = residual;
    pImpl->mHasResidual = true;
}

std::chrono::nanoseconds Arrival::getResidual() const
{
    if (!hasResidual()){throw std::runtime_error("Residual not set");}
    return pImpl->mResidual;
}

bool Arrival::hasResidual() const noexcept
{
    return pImpl->mHasResidual;
}