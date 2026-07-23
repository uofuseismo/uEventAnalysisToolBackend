#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_DURATION_MAGNITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_DURATION_MAGNITUDE_HPP
#include <uEventAnalysisToolBackend/database/aqms/magnitude.hpp>
#include <memory>
namespace UEventAnalysisToolBackend::Database::AQMS
{ 
 class StationDurationMagnitude; 
}
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @class DurationMagnitude durationMagnitude.hpp
/// @brief Defines a duration magnitude.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class DurationMagnitude final : public IMagnitude
{
    // TODO make the observations iterable
public:
    /// @brief Constructor.
    DurationMagnitude();
    /// @brief Copy constructor.
    DurationMagnitude(const DurationMagnitude &magnitude); 
    /// @brief Move constructor.
    DurationMagnitude(DurationMagnitude &&magnitude) noexcept;

    /// @result A type of duration magnitude.
    [[nodiscard]] IMagnitude::Type getType() const noexcept final;

    /// @result A deep copy of this duration magnitude.
    [[nodiscard]] std::unique_ptr<IMagnitude> clone() const final;

    /// @brief Sets the station magnitudes.
    /// @note The actual duration magnitude ends up being an average
    ///       of these values.
    void setStationMagnitudes(const std::vector<StationDurationMagnitude> &stationMagnitudes);
    void setStationMagnitudes(std::vector<StationDurationMagnitude> &&stationMagnitudes);
    /// @result The station magnitudes.
    [[nodiscard]] std::vector<StationDurationMagnitude> getStationMagnitudes() const;


    /// @brief Destructor.
    virtual ~DurationMagnitude();
    /// @brief Copy assignment.
    DurationMagnitude& operator=(const DurationMagnitude &magnitude);
    /// @brief Move assignment.
    DurationMagnitude& operator=(DurationMagnitude &&) noexcept;
private:
    class DurationMagnitudeImpl;
    std::unique_ptr<DurationMagnitudeImpl> pImpl;
};
}
#endif
