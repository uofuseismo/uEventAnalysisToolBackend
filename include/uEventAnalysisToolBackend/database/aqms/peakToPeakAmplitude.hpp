#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_PEAK_TO_PEAK_AMPLITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_PEAK_TO_PEAK_AMPLITUDE_HPP
#include <chrono>
#include <memory>
#include <utility>
namespace UEventAnalysisToolBackend::Database::AQMS
{
 class StreamIdentifier;
}
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @class PeakToPeakAmplitude peakToPeakAmplitude.hpp
/// @brief A peak-to-peak amplitude observation on a channel observation.
///        At UUSS these are used in pairs (e.g., HHE and HHN) to make a
///        StationLocalMagnitude.
/// @copyright Ben Baker (University of Utah) distributed under the MIT NO AI
///            license.
class PeakToPeakAmplitude
{
public:
    /// @brief The units associated with the (displacement) amplitude measurement.
    enum class Units
    {
        Meters,      /*!< Units are in meters - these are converted to millimeters. */
        Centimeters, /*!< Units are in centimeters - these are converted to millimeters. */
        Millimeters  /*!< Units are millimeters. */
    };
public:
    /// @brief Constructor.
    PeakToPeakAmplitude();
    /// @brief Copy constructor.    
    PeakToPeakAmplitude(const PeakToPeakAmplitude &amplitude);
    /// @brief Move constructor.
    PeakToPeakAmplitude(PeakToPeakAmplitude &&amplitude) noexcept;

    /// @brief Sets the stream identifier on which the observation was made.
    void setStreamIdentifier(const StreamIdentifier &identifier);
    /// @result The stream identifier.
    /// @throws std::runtime_error if \c hasStreamIdentifier() is false.
    [[nodiscard]] StreamIdentifier getStreamIdentifier() const;
    /// @result True indicates the stream identifier was set.
    [[nodiscard]] bool hasStreamIdentifier() const noexcept;

    /// @brief Sets the times in the waveform that the first and
    ///        and second amplitudes were recorded.
    void setPeakTimes(const std::pair<std::chrono::nanoseconds,
                                      std::chrono::nanoseconds> &peakTimes);
    /// @result The peak times.
    /// @throws std::runtime_error if \c hasPeakTimes() is false.
    [[nodiscard]] std::pair<std::chrono::nanoseconds, std::chrono::nanoseconds> getPeakTimes() const;
    /// @result True indicates the peak times were set.
    [[nodiscard]] bool hasPeakTimes() const noexcept;

    /// @brief The observed (peak to peak) amplitude.
    /// @param[in] amplitude  The observed amplitude.
    /// @param[in] untis      The corresponding units on the amplitude.
    /// @throws std::invalid_argument if this is not positive.
    void setAmplitude(double amplitude, const Units units);
    /// @result The observed amplitude in millimeters.
    /// @throws std::runtime_error if \c hasAmplitude() is false.
    [[nodiscard]] double getAmplitude() const;
    /// @result True indicates the amplitude was set.
    [[nodiscard]] bool hasAmplitude() const noexcept;

    /// @brief Destructor.
    ~PeakToPeakAmplitude();
 
    /// @brief Copy assignment.
    PeakToPeakAmplitude& operator=(const PeakToPeakAmplitude &amplitude);
    /// @breif Move assignment.
    PeakToPeakAmplitude& operator=(PeakToPeakAmplitude &&amplitude) noexcept;
private:
    class PeakToPeakAmplitudeImpl;
    std::unique_ptr<PeakToPeakAmplitudeImpl> pImpl;
};
}
#endif
