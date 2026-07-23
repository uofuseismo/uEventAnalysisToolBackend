#include <memory>
#include <utility>
#include <vector>
#include "uEventAnalysisToolBackend/database/aqms/durationMagnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/magnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/stationDurationMagnitude.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

class DurationMagnitude::DurationMagnitudeImpl
{
public:
    std::vector<StationDurationMagnitude> mStationMagnitudes;
};

/// Constructor
DurationMagnitude::DurationMagnitude() :
    IMagnitude(),
    pImpl(std::make_unique<DurationMagnitudeImpl> ())
{
}

/// Copy constructor
DurationMagnitude::DurationMagnitude(const DurationMagnitude &magnitude) :
    IMagnitude(magnitude),
    pImpl(std::make_unique<DurationMagnitudeImpl> (*magnitude.pImpl))
{
}

/// Move constructor
DurationMagnitude::DurationMagnitude(DurationMagnitude &&magnitude) noexcept
{
    *this = std::move(magnitude);
}

/// Copy assignment
DurationMagnitude&
DurationMagnitude::operator=(const DurationMagnitude &magnitude)
{
    if (&magnitude == this){return *this;}
    IMagnitude::operator=(magnitude);
    pImpl = std::make_unique<DurationMagnitudeImpl> (*magnitude.pImpl);
    return *this;
}

/// Move assignment
DurationMagnitude&
DurationMagnitude::operator=(DurationMagnitude &&magnitude) noexcept
{
    if (&magnitude == this){return *this;}
    pImpl = std::move(magnitude.pImpl);
    IMagnitude::operator=(std::move(magnitude));
    return *this;
}

/// Destructor
DurationMagnitude::~DurationMagnitude() = default;

/// Type
IMagnitude::Type DurationMagnitude::getType() const noexcept
{
    return IMagnitude::Type::Duration;
}

/// Clone
std::unique_ptr<IMagnitude> DurationMagnitude::clone() const
{
    return std::make_unique<DurationMagnitude> (*this);
}

/// Station magnitudes
void DurationMagnitude::setStationMagnitudes(
    const std::vector<StationDurationMagnitude> &stationMagnitudes)
{
    pImpl->mStationMagnitudes = stationMagnitudes;
}

void DurationMagnitude::setStationMagnitudes(
    std::vector<StationDurationMagnitude> &&stationMagnitudes)
{
    pImpl->mStationMagnitudes = std::move(stationMagnitudes);
}

std::vector<StationDurationMagnitude>
DurationMagnitude::getStationMagnitudes() const
{
    return pImpl->mStationMagnitudes;
}