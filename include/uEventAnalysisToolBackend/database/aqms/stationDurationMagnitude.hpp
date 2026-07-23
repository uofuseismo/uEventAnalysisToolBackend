#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_STATION_DURATION_MAGNITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_STATION_DURATION_MAGNITUDE_HPP
#include <memory>
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @brief Defines a station duration magnitude.  The station magnitude at 
///        Utah is computed as follows:
///           -2.25 + 2.32*log10(duration) + 0.0023*distance_km + channelMagCorrection
///        and in YNP
///           -2.60 + 2.44 log10(duration) + 0.0040*distance_km + channelMagCorrection
///         
class StationDurationMagnitude
{
public:
    /// @brief Constructor.
    StationDurationMagnitude();
    /// @brief Copy constructor.
    StationDurationMagnitude(const StationDurationMagnitude &magnitude); 
    /// @brief Move constructor.
    StationDurationMagnitude(StationDurationMagnitude &&magnitude) noexcept;

    /// @brief The coda duration (tau in the database).
    /// @param[in] duration  The duration in seconds.
    /// @throws std::invalid_argument if the duration is not positive.
    void setDuration(double duration);
    /// @result The duration in seconds.
    /// @throws std::runtime_error if \c hasDuration() is false.
    [[nodiscard]] double getDuration() const;
    /// @result True indicates the duration was set.
    [[nodiscard]] bool hasDuration() const noexcept;

    /// @brief The source-receiver distance in meters.
    /// @throws std::invalid_argument if this is negative.
    void setDistance(double distance);
    /// @result The source-receiver distance in meters.
    /// @throws std::runtime_error if \c hasDistance() is false.
    [[nodiscard]] double getDistance() const noexcept;
    /// @result True indicates the source-receiver distance was set.
    [[nodiscard]] bool hasDistance() const noexcept;

    /// @brief Sets the magnitude correction.
    /// @param[in] correction  The corretion to add to the magnitude.
    void setCorrection(double correction) noexcept;
    /// @result The station correction.  By default this is 0 since these
    ///         are not used at UUSS. 
    [[nodiscard]] double getCorrection() const noexcept;

    /// @brief Sets the residual magnitude (observed - estimated) where
    ///        "estimated" is effectively an average of the individual
    ///        station magnitudes.
    void setResidual(double residual) noexcept;
    /// @result The residual magnitude.
    [[nodiscard]] double getResidual() const;
    /// @result True indicates the residual was set.
    [[nodiscard]] bool hasResidual() const noexcept;

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
    ~StationDurationMagnitude();
    /// @brief Copy assignment.
    StationDurationMagnitude& operator=(const StationDurationMagnitude &magnitude);
    /// @brief Move assignment.
    StationDurationMagnitude& operator=(StationDurationMagnitude &&) noexcept;
private:
    class StationDurationMagnitudeImpl;
    std::unique_ptr<StationDurationMagnitudeImpl> pImpl;
};
}
#endif
