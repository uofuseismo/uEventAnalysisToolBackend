#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_DURATION_MAGNITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_DURATION_MAGNITUDE_HPP
#include <uEventAnalysisToolBackend/database/aqms/magnitude.hpp>
#include <memory>
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @brief Defines a duration magnitude.
class DurationMagnitude final : public IMagnitude
{
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
