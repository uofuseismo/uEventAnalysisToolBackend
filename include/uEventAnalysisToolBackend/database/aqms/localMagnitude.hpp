#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_LOCAL_MAGNITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_LOCAL_MAGNITUDE_HPP
#include <uEventAnalysisToolBackend/database/aqms/magnitude.hpp>
#include <memory>
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @brief Defines a local (Richter) magnitude.
class LocalMagnitude final : public IMagnitude
{
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
