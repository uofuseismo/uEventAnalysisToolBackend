#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_STATION_LOCAL_MAGNITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_STATION_LOCAL_MAGNITUDE_HPP
#include <memory>
#include <utility>
namespace UEventAnalysisToolBackend::Database::AQMS
{   
 class PeakToPeakAmplitude;
}
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @class StationLocalMagnitude stationLocalMagnitude.hpp
/// @brief Defines a local (Richter) magnitude made by an individual stream.
///        To compute a local magnitude we use something like:
///          M_L = \log_{10} (A) + C_d + C_s
///        where A is a (half) amplitude from a WoodAnderson seismometer,
///        C_d is a distance correction and C_s is a station correction.
///        So for example, if you take \c getAmplitude() on TCU HHN
///        and get an amplitude of 6.434 mm and take \c getAmplitude()
///        on TCU HHE and get 3.180 mm.  Then, at Utah, we compute an
///        average of the channels to get the station magnitude - i.e.
///        two channels make one A by averaging half amplitudes ala
///           A = (6.434/2 + 3.180/2)/2
///        A distance correction at, say, 177 km from a lookup table produces
///           C_d = 3.4
///        And the station's correction is 
///           C_s =-0.55
///        Put it all together and then the station magnitude from the two
///        channels is:
///           log10( (6.434/2 + 3.180/2)/2 ) + 3.4 + (-0.55) = 3.23 
///        If the network magnitude is 3.45 then the residual is
///        3.45 - 3.23 = 0.22
///           
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI License.
class StationLocalMagnitude
{
public:
    /// @brief Constructor.
    StationLocalMagnitude();
    /// @brief Copy constructor.
    StationLocalMagnitude(const StationLocalMagnitude &magnitude); 
    /// @brief Move constructor.
    StationLocalMagnitude(StationLocalMagnitude &&magnitude) noexcept;

    /// @brief Sets the amplitude measurements made on two channels.
    /// @throws std::invalid_argument if the amplitudes are from the same
    ///         stream, do not have peak times, or amplitude values.
    void setPeakToPeakAmplitudes(const std::pair<PeakToPeakAmplitude, PeakToPeakAmplitude> &amplitudes);
    /// @result The amplitude measurements made on two channels.
    /// @throws std::runtime_error if \c hasPeakToPeakAmplitudes() is false.
    [[nodiscard]] std::pair<PeakToPeakAmplitude, PeakToPeakAmplitude> getPeakToPeakAmplitudes() const;
    /// @result True indicates the channel amplitudes were set.
    [[nodiscard]] bool hasPeakToPeakAmplitudes() const noexcept;

    /// @brief Sets the weight.  This is typically binary 0 or 1.
    /// @param[in] weight  The weight where 0 is disabled and 1 fully utilized.
    /// @throws std::invalid_argument if this is not in the range of [0, 1].
    void setWeight(double weight);
    /// @result The weight.
    /// @throws std::runtime_error if \c hasWeight() is false.
    [[nodiscard]] double getWeight() const;
    /// @result True indicates the weight was set.
    [[nodiscard]] bool hasWeight() const noexcept;

    /// @brief Destructor.
    ~StationLocalMagnitude();
    /// @brief Copy assignment.
    StationLocalMagnitude& operator=(const StationLocalMagnitude &magnitude);
    /// @brief Move assignment.
    StationLocalMagnitude& operator=(StationLocalMagnitude &&) noexcept;
private:
    class StationLocalMagnitudeImpl;
    std::unique_ptr<StationLocalMagnitudeImpl> pImpl;
};
}
#endif
