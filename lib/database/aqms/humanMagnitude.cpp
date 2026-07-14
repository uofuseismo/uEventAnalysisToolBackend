#include <memory>
#include <utility>
#include "uEventAnalysisToolBackend/database/aqms/humanMagnitude.hpp"
#include "uEventAnalysisToolBackend/database/aqms/magnitude.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

class HumanMagnitude::HumanMagnitudeImpl
{
};

/// Constructor
HumanMagnitude::HumanMagnitude() :
    IMagnitude(),
    pImpl(std::make_unique<HumanMagnitudeImpl> ())
{
}

/// Copy constructor
HumanMagnitude::HumanMagnitude(const HumanMagnitude &magnitude) :
    IMagnitude(magnitude),
    pImpl(std::make_unique<HumanMagnitudeImpl> (*magnitude.pImpl))
{
}

/// Move constructor
HumanMagnitude::HumanMagnitude(HumanMagnitude &&magnitude) noexcept
{
    *this = std::move(magnitude);
}

/// Copy assignment
HumanMagnitude& HumanMagnitude::operator=(const HumanMagnitude &magnitude)
{
    if (&magnitude == this){return *this;}
    IMagnitude::operator=(magnitude);
    pImpl = std::make_unique<HumanMagnitudeImpl> (*magnitude.pImpl);
    return *this;
}

/// Move assignment
HumanMagnitude& HumanMagnitude::operator=(HumanMagnitude &&magnitude) noexcept
{
    if (&magnitude == this){return *this;}
    pImpl = std::move(magnitude.pImpl);
    IMagnitude::operator=(std::move(magnitude));
    return *this;
}

/// Destructor
HumanMagnitude::~HumanMagnitude() = default;

/// Type
IMagnitude::Type HumanMagnitude::getType() const noexcept
{
    return IMagnitude::Type::Human;
}

/// Clone
std::unique_ptr<IMagnitude> HumanMagnitude::clone() const
{
    return std::make_unique<HumanMagnitude> (*this);
}

/// Review status - a human-assigned magnitude is human-reviewed by definition.
IMagnitude::ReviewStatus HumanMagnitude::getReviewStatus() const noexcept
{
    return IMagnitude::ReviewStatus::Human;
}