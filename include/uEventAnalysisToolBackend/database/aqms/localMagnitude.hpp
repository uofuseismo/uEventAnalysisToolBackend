#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_LOCAL_MAGNITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_LOCAL_MAGNITUDE_HPP
#include <uEventAnalysisToolBackend/database/aqms/magnitude.hpp>
#include <memory>
namespace UEventAnalysisToolBackend::Database::AQMS
{   
 class StationLocalMagnitude;
}
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @class LocalMagnitude localMagnitude.hpp
/// @brief Defines a local (Richter) magnitude.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI License.
class LocalMagnitude final : public IMagnitude
{
    // TODO Make an iterator based on std::vector so i can iterate through station mags
public:
    /// @brief Constructor.
    LocalMagnitude();
    /// @brief Copy constructor.
    LocalMagnitude(const LocalMagnitude &magnitude); 
    /// @brief Move constructor.
    LocalMagnitude(LocalMagnitude &&magnitude) noexcept;

    /// @result A type of local magnitude.
    [[nodiscard]] IMagnitude::Type getType() const noexcept final;

    /// @result A deep copy of this local magnitude.
    [[nodiscard]] std::unique_ptr<IMagnitude> clone() const final;

    /// @brief Sets the station magnitudes.
    /// @note The actual local magnitude ends up being something akin
    ///       to an average of these values.
    void setStationMagnitudes(const std::vector<StationLocalMagnitude> &stationMagnitudes);
    void setStationMagnitudes(std::vector<StationLocalMagnitude> &&stationMagnitudes);
    /// @result The station magnitudes.
    [[nodiscard]] std::vector<StationLocalMagnitude> getStationMagnitudes() const;

    /// @brief Destructor.
    virtual ~LocalMagnitude();
    /// @brief Copy assignment.
    LocalMagnitude& operator=(const LocalMagnitude &magnitude);
    /// @brief Move assignment.
    LocalMagnitude& operator=(LocalMagnitude &&) noexcept;
private:
    class LocalMagnitudeImpl;
    std::unique_ptr<LocalMagnitudeImpl> pImpl;
};
}
#endif
