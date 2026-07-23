#include <chrono>
#include <memory>
#include <stdexcept>
#include <utility>
#include "uEventAnalysisToolBackend/database/aqms/peakToPeakAmplitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/streamIdentifier.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

namespace
{
/// @brief Converts an amplitude in the given units to millimeters.
[[nodiscard]] double toMillimeters(const double amplitude,
                                   const PeakToPeakAmplitude::Units units)
{
    switch (units)
    {
    case PeakToPeakAmplitude::Units::Meters:
        return amplitude*1000.0;
    case PeakToPeakAmplitude::Units::Centimeters:
        return amplitude*10.0;
    case PeakToPeakAmplitude::Units::Millimeters:
        return amplitude;
    }
    return amplitude;
}
}

class PeakToPeakAmplitude::PeakToPeakAmplitudeImpl
{
public:
    StreamIdentifier mStreamIdentifier;
    std::pair<std::chrono::nanoseconds, std::chrono::nanoseconds> mPeakTimes;
    double mAmplitude{0};
    bool mHasStreamIdentifier{false};
    bool mHasPeakTimes{false};
    bool mHasAmplitude{false};
};

/// Constructor
PeakToPeakAmplitude::PeakToPeakAmplitude() :
    pImpl(std::make_unique<PeakToPeakAmplitudeImpl> ())
{
}

/// Copy constructor
PeakToPeakAmplitude::PeakToPeakAmplitude(const PeakToPeakAmplitude &amplitude)
{
    *this = amplitude;
}

/// Move constructor
PeakToPeakAmplitude::PeakToPeakAmplitude(
    PeakToPeakAmplitude &&amplitude) noexcept
{
    *this = std::move(amplitude);
}

/// Copy assignment
PeakToPeakAmplitude&
PeakToPeakAmplitude::operator=(const PeakToPeakAmplitude &amplitude)
{
    if (&amplitude == this){return *this;}
    pImpl = std::make_unique<PeakToPeakAmplitudeImpl> (*amplitude.pImpl);
    return *this;
}

/// Move assignment
PeakToPeakAmplitude&
PeakToPeakAmplitude::operator=(PeakToPeakAmplitude &&amplitude) noexcept
{
    if (&amplitude == this){return *this;}
    pImpl = std::move(amplitude.pImpl);
    return *this;
}

/// Destructor
PeakToPeakAmplitude::~PeakToPeakAmplitude() = default;

/// Stream identifier
void PeakToPeakAmplitude::setStreamIdentifier(const StreamIdentifier &identifier)
{
    pImpl->mStreamIdentifier = identifier;
    pImpl->mHasStreamIdentifier = true;
}

StreamIdentifier PeakToPeakAmplitude::getStreamIdentifier() const
{
    if (!hasStreamIdentifier())
    {
        throw std::runtime_error("Stream identifier not set");
    }
    return pImpl->mStreamIdentifier;
}

bool PeakToPeakAmplitude::hasStreamIdentifier() const noexcept
{
    return pImpl->mHasStreamIdentifier;
}

/// Peak times
void PeakToPeakAmplitude::setPeakTimes(
    const std::pair<std::chrono::nanoseconds,
                    std::chrono::nanoseconds> &peakTimes)
{
    pImpl->mPeakTimes = peakTimes;
    pImpl->mHasPeakTimes = true;
}

std::pair<std::chrono::nanoseconds, std::chrono::nanoseconds>
PeakToPeakAmplitude::getPeakTimes() const
{
    if (!hasPeakTimes()){throw std::runtime_error("Peak times not set");}
    return pImpl->mPeakTimes;
}

bool PeakToPeakAmplitude::hasPeakTimes() const noexcept
{
    return pImpl->mHasPeakTimes;
}

/// Amplitude
void PeakToPeakAmplitude::setAmplitude(const double amplitude,
                                       const Units units)
{
    if (amplitude <= 0)
    {
        throw std::invalid_argument("Amplitude must be positive");
    }
    pImpl->mAmplitude = toMillimeters(amplitude, units);
    pImpl->mHasAmplitude = true;
}

double PeakToPeakAmplitude::getAmplitude() const
{
    if (!hasAmplitude()){throw std::runtime_error("Amplitude not set");}
    return pImpl->mAmplitude;
}

bool PeakToPeakAmplitude::hasAmplitude() const noexcept
{
    return pImpl->mHasAmplitude;
}
