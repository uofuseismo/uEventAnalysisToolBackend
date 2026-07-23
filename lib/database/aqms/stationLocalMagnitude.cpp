#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include "uEventAnalysisToolBackend/database/aqms/stationLocalMagnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/peakToPeakAmplitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/streamIdentifier.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

namespace
{
/// @brief A stream identifier's four codes as a comparable tuple; an unset
///        code is treated as an empty string.
[[nodiscard]] std::string streamKey(const StreamIdentifier &identifier)
{
    const std::string network{identifier.hasNetwork() ?
                             identifier.getNetwork() : ""};
    const std::string station{identifier.hasStation() ?
                             identifier.getStation() : ""};
    const std::string channel{identifier.hasChannel() ?
                             identifier.getChannel() : ""};
    const std::string locationCode{identifier.hasLocationCode() ?
                                  identifier.getLocationCode() : ""};
    return network + "." + station + "." + channel + "." + locationCode;
}
}

class StationLocalMagnitude::StationLocalMagnitudeImpl
{
public:
    std::pair<PeakToPeakAmplitude, PeakToPeakAmplitude> mAmplitudes;
    double mWeight{0};
    bool mHasAmplitudes{false};
    bool mHasWeight{false};
};

/// Constructor
StationLocalMagnitude::StationLocalMagnitude() :
    pImpl(std::make_unique<StationLocalMagnitudeImpl> ())
{
}

/// Copy constructor
StationLocalMagnitude::StationLocalMagnitude(
    const StationLocalMagnitude &magnitude)
{
    *this = magnitude;
}

/// Move constructor
StationLocalMagnitude::StationLocalMagnitude(
    StationLocalMagnitude &&magnitude) noexcept
{
    *this = std::move(magnitude);
}

/// Copy assignment
StationLocalMagnitude&
StationLocalMagnitude::operator=(const StationLocalMagnitude &magnitude)
{
    if (&magnitude == this){return *this;}
    pImpl = std::make_unique<StationLocalMagnitudeImpl> (*magnitude.pImpl);
    return *this;
}

/// Move assignment
StationLocalMagnitude&
StationLocalMagnitude::operator=(StationLocalMagnitude &&magnitude) noexcept
{
    if (&magnitude == this){return *this;}
    pImpl = std::move(magnitude.pImpl);
    return *this;
}

/// Destructor
StationLocalMagnitude::~StationLocalMagnitude() = default;

/// Peak-to-peak amplitudes
void StationLocalMagnitude::setPeakToPeakAmplitudes(
    const std::pair<PeakToPeakAmplitude, PeakToPeakAmplitude> &amplitudes)
{
    const auto &first = amplitudes.first;
    const auto &second = amplitudes.second;
    if (!first.hasStreamIdentifier() || !second.hasStreamIdentifier())
    {
        throw std::invalid_argument(
            "Both amplitudes must have a stream identifier");
    }
    if (streamKey(first.getStreamIdentifier())
        == streamKey(second.getStreamIdentifier()))
    {
        throw std::invalid_argument(
            "The two amplitudes must be from different streams");
    }
    if (!first.hasPeakTimes() || !second.hasPeakTimes())
    {
        throw std::invalid_argument("Both amplitudes must have peak times");
    }
    if (!first.hasAmplitude() || !second.hasAmplitude())
    {
        throw std::invalid_argument(
            "Both amplitudes must have an amplitude value");
    }
    pImpl->mAmplitudes = amplitudes;
    pImpl->mHasAmplitudes = true;
}

std::pair<PeakToPeakAmplitude, PeakToPeakAmplitude>
StationLocalMagnitude::getPeakToPeakAmplitudes() const
{
    if (!hasPeakToPeakAmplitudes())
    {
        throw std::runtime_error("Peak-to-peak amplitudes not set");
    }
    return pImpl->mAmplitudes;
}

bool StationLocalMagnitude::hasPeakToPeakAmplitudes() const noexcept
{
    return pImpl->mHasAmplitudes;
}

/// Weight
void StationLocalMagnitude::setWeight(const double weight)
{
    if (weight < 0 || weight > 1)
    {
        throw std::invalid_argument("Weight must be in the range [0, 1]");
    }
    pImpl->mWeight = weight;
    pImpl->mHasWeight = true;
}

double StationLocalMagnitude::getWeight() const
{
    if (!hasWeight()){throw std::runtime_error("Weight not set");}
    return pImpl->mWeight;
}

bool StationLocalMagnitude::hasWeight() const noexcept
{
    return pImpl->mHasWeight;
}