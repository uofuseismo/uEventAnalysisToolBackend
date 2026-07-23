#include <memory>
#include <stdexcept>
#include <utility>
#include "uEventAnalysisToolBackend/database/aqms/stationDurationMagnitude.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

class StationDurationMagnitude::StationDurationMagnitudeImpl
{
public:
    double mDuration{0};
    double mDistance{0};
    double mCorrection{0};
    double mResidual{0};
    double mWeight{0};
    bool mHasDuration{false};
    bool mHasDistance{false};
    bool mHasResidual{false};
    bool mHasWeight{false};
};

/// Constructor
StationDurationMagnitude::StationDurationMagnitude() :
    pImpl(std::make_unique<StationDurationMagnitudeImpl> ())
{
}

/// Copy constructor
StationDurationMagnitude::StationDurationMagnitude(
    const StationDurationMagnitude &magnitude)
{
    *this = magnitude;
}

/// Move constructor
StationDurationMagnitude::StationDurationMagnitude(
    StationDurationMagnitude &&magnitude) noexcept
{
    *this = std::move(magnitude);
}

/// Copy assignment
StationDurationMagnitude&
StationDurationMagnitude::operator=(const StationDurationMagnitude &magnitude)
{
    if (&magnitude == this){return *this;}
    pImpl = std::make_unique<StationDurationMagnitudeImpl> (*magnitude.pImpl);
    return *this;
}

/// Move assignment
StationDurationMagnitude&
StationDurationMagnitude::operator=(
    StationDurationMagnitude &&magnitude) noexcept
{
    if (&magnitude == this){return *this;}
    pImpl = std::move(magnitude.pImpl);
    return *this;
}

/// Destructor
StationDurationMagnitude::~StationDurationMagnitude() = default;

/// Duration
void StationDurationMagnitude::setDuration(const double duration)
{
    if (duration <= 0)
    {
        throw std::invalid_argument("Duration must be positive");
    }
    pImpl->mDuration = duration;
    pImpl->mHasDuration = true;
}

double StationDurationMagnitude::getDuration() const
{
    if (!hasDuration()){throw std::runtime_error("Duration not set");}
    return pImpl->mDuration;
}

bool StationDurationMagnitude::hasDuration() const noexcept
{
    return pImpl->mHasDuration;
}

/// Distance
void StationDurationMagnitude::setDistance(const double distance)
{
    if (distance < 0)
    {
        throw std::invalid_argument("Distance cannot be negative");
    }
    pImpl->mDistance = distance;
    pImpl->mHasDistance = true;
}

double StationDurationMagnitude::getDistance() const noexcept
{
    return pImpl->mDistance;
}

bool StationDurationMagnitude::hasDistance() const noexcept
{
    return pImpl->mHasDistance;
}

/// Correction
void StationDurationMagnitude::setCorrection(const double correction) noexcept
{
    pImpl->mCorrection = correction;
}

double StationDurationMagnitude::getCorrection() const noexcept
{
    return pImpl->mCorrection;
}

/// Residual
void StationDurationMagnitude::setResidual(const double residual) noexcept
{
    pImpl->mResidual = residual;
    pImpl->mHasResidual = true;
}

double StationDurationMagnitude::getResidual() const
{
    if (!hasResidual()){throw std::runtime_error("Residual not set");}
    return pImpl->mResidual;
}

bool StationDurationMagnitude::hasResidual() const noexcept
{
    return pImpl->mHasResidual;
}

/// Weight
void StationDurationMagnitude::setWeight(const double weight)
{
    if (weight < 0 || weight > 1)
    {
        throw std::invalid_argument("Weight must be in the range [0, 1]");
    }
    pImpl->mWeight = weight;
    pImpl->mHasWeight = true;
}

double StationDurationMagnitude::getWeight() const
{
    if (!hasWeight()){throw std::runtime_error("Weight not set");}
    return pImpl->mWeight;
}

bool StationDurationMagnitude::hasWeight() const noexcept
{
    return pImpl->mHasWeight;
}