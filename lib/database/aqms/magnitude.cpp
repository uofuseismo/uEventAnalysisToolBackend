#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include "uEventAnalysisToolBackend/database/aqms/magnitude.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

namespace
{
constexpr double maximumMagnitude{11};
}

class IMagnitude::IMagnitudeImpl
{
public:
    int64_t mIdentifier{0};
    double mValue{0};
    ReviewStatus mReviewStatus{ReviewStatus::Automatic};
    bool mHasIdentifier{false};
    bool mHasValue{false};
    bool mHasReviewStatus{false};
    bool mPreferred{true};
};

/// Constructor
IMagnitude::IMagnitude() :
    pImpl(std::make_unique<IMagnitudeImpl> ())
{
}

/// Copy constructor
IMagnitude::IMagnitude(const IMagnitude &magnitude)
{
    *this = magnitude;
}

/// Move constructor
IMagnitude::IMagnitude(IMagnitude &&magnitude) noexcept
{
    *this = std::move(magnitude);
}

/// Copy assignment
IMagnitude& IMagnitude::operator=(const IMagnitude &magnitude)
{
    if (&magnitude == this){return *this;}
    pImpl = std::make_unique<IMagnitudeImpl> (*magnitude.pImpl);
    return *this;
}

/// Move assignment
IMagnitude& IMagnitude::operator=(IMagnitude &&magnitude) noexcept
{
    if (&magnitude == this){return *this;}
    pImpl = std::move(magnitude.pImpl);
    return *this;
}

/// Destructor
IMagnitude::~IMagnitude() = default;

/// Identifier
void IMagnitude::setIdentifier(const int64_t identifier)
{
    pImpl->mIdentifier = identifier;
    pImpl->mHasIdentifier = true;
}

int64_t IMagnitude::getIdentifier() const
{
    if (!hasIdentifier()){throw std::runtime_error("Magnitude identifier not set");}
    return pImpl->mIdentifier;
}

bool IMagnitude::hasIdentifier() const noexcept
{
    return pImpl->mHasIdentifier;
}

/// Value
void IMagnitude::setValue(const double value)
{
    if (value > maximumMagnitude)
    {
        throw std::invalid_argument("Magnitude cannot exceed "
                                  + std::to_string(maximumMagnitude));
    }
    pImpl->mValue = value;
    pImpl->mHasValue = true;
}

double IMagnitude::getValue() const
{
    if (!hasValue()){throw std::runtime_error("Magnitude value not set");}
    return pImpl->mValue;
}

bool IMagnitude::hasValue() const noexcept
{
    return pImpl->mHasValue;
}

/// Review status
void IMagnitude::setReviewStatus(const ReviewStatus status) noexcept
{
    pImpl->mReviewStatus = status;
    pImpl->mHasReviewStatus = true;
}

IMagnitude::ReviewStatus IMagnitude::getReviewStatus() const
{
    if (!hasReviewStatus()){throw std::runtime_error("Review status not set");}
    return pImpl->mReviewStatus;
}

bool IMagnitude::hasReviewStatus() const noexcept
{
    return pImpl->mHasReviewStatus;
}

/// Preferred
void IMagnitude::setIsPreferred() noexcept
{
    pImpl->mPreferred = true;
}

void IMagnitude::setNotPreferred() noexcept
{
    pImpl->mPreferred = false;
}

bool IMagnitude::isPreferred() const noexcept
{
    return pImpl->mPreferred;
}