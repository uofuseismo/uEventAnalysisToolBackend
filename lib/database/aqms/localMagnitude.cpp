#include <memory>
#include <utility>
#include <vector>
#include "uEventAnalysisToolBackend/database/aqms/localMagnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/magnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/stationLocalMagnitude.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

class LocalMagnitude::LocalMagnitudeImpl
{
public:
    std::vector<StationLocalMagnitude> mStationMagnitudes;
};

/// Constructor
LocalMagnitude::LocalMagnitude() :
    IMagnitude(),
    pImpl(std::make_unique<LocalMagnitudeImpl> ())
{
}

/// Copy constructor
LocalMagnitude::LocalMagnitude(const LocalMagnitude &magnitude) :
    IMagnitude(magnitude),
    pImpl(std::make_unique<LocalMagnitudeImpl> (*magnitude.pImpl))
{
}

/// Move constructor
LocalMagnitude::LocalMagnitude(LocalMagnitude &&magnitude) noexcept
{
    *this = std::move(magnitude);
}

/// Copy assignment
LocalMagnitude& LocalMagnitude::operator=(const LocalMagnitude &magnitude)
{
    if (&magnitude == this){return *this;}
    IMagnitude::operator=(magnitude);
    pImpl = std::make_unique<LocalMagnitudeImpl> (*magnitude.pImpl);
    return *this;
}

/// Move assignment
LocalMagnitude& LocalMagnitude::operator=(LocalMagnitude &&magnitude) noexcept
{
    if (&magnitude == this){return *this;}
    pImpl = std::move(magnitude.pImpl);
    IMagnitude::operator=(std::move(magnitude));
    return *this;
}

/// Destructor
LocalMagnitude::~LocalMagnitude() = default;

/// Type
IMagnitude::Type LocalMagnitude::getType() const noexcept
{
    return IMagnitude::Type::Local;
}

/// Clone
std::unique_ptr<IMagnitude> LocalMagnitude::clone() const
{
    return std::make_unique<LocalMagnitude> (*this);
}

/// Station magnitudes
void LocalMagnitude::setStationMagnitudes(
    const std::vector<StationLocalMagnitude> &stationMagnitudes)
{
    pImpl->mStationMagnitudes = stationMagnitudes;
}

void LocalMagnitude::setStationMagnitudes(
    std::vector<StationLocalMagnitude> &&stationMagnitudes)
{
    pImpl->mStationMagnitudes = std::move(stationMagnitudes);
}

std::vector<StationLocalMagnitude>
LocalMagnitude::getStationMagnitudes() const
{
    return pImpl->mStationMagnitudes;
}