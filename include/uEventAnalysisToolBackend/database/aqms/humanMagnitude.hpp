#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_HUMAN_MAGNITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_HUMAN_MAGNITUDE_HPP
#include <uEventAnalysisToolBackend/database/aqms/magnitude.hpp>
#include <memory>
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @brief Defines a human assigned magnitude.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class HumanMagnitude final : public IMagnitude
{
public:
    /// @brief Constructor.
    HumanMagnitude();
    /// @brief Copy constructor.
    HumanMagnitude(const HumanMagnitude &magnitude); 
    /// @brief Move constructor.
    HumanMagnitude(HumanMagnitude &&magnitude) noexcept;

    /// @result A type of human magnitude.
    [[nodiscard]] IMagnitude::Type getType() const noexcept final;

    /// @result A deep copy of this human magnitude.
    [[nodiscard]] std::unique_ptr<IMagnitude> clone() const final;

    /// @result By definition if a human assigned it then it must be human reviewed.
    [[nodiscard]] IMagnitude::ReviewStatus getReviewStatus() const noexcept override final;

    /// @brief Destructor.
    virtual ~HumanMagnitude();
    /// @brief Copy assignment.
    HumanMagnitude& operator=(const HumanMagnitude &magnitude);
    /// @brief Move assignment.
    HumanMagnitude& operator=(HumanMagnitude &&) noexcept;
private:
    class HumanMagnitudeImpl;
    std::unique_ptr<HumanMagnitudeImpl> pImpl;
};
}
#endif
