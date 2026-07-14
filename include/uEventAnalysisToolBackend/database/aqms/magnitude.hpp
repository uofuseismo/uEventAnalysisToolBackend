#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_MAGNITUDE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_MAGNITUDE_HPP 
#include <cstdint>
#include <memory>
#include <vector>
namespace UEventAnalysisToolBackend::Database::AQMS
{

/// @brief There are a handful of magnitudes.  Typically we just want to know
///        how big and which one.  Hence, we'll use inheritance.
/// @copyright Ben Baker (Unviersity of Utah) distributed under the
///            MIT NO AI license.
class IMagnitude
{
public:
    /// @brief The magnitude type.  I've purged energy and "n" because
    ///        we don't use them (though a handful might exist in our 
    ///        full database.
    enum class Type
    {
        Human,    /*!< This is a human assigned magnitude - i.e,. Mh. */
        Duration, /*!< A duration magnitude - i.e., Md. */
        Local,    /*!< A local (Richter) magnitude - i.e., Ml. */
        Moment    /*!< This is a moment magnitude - ie., Mw. */
    };
    /// @brief Defines the review status.
    enum class ReviewStatus
    {
        Automatic, /*!< This is an automatically generated magnitude. */
        Human      /*!< This is a human-reviewed magnitude. */
    };  
public:
    /// @brief Constructor.
    IMagnitude();
    /// @brief Copy constructor.
    IMagnitude(const IMagnitude &magnitude);
    /// @brief Move constructor.
    IMagnitude(IMagnitude &&mangnitude) noexcept;

    /// @brief Sets the magnitude identifier.
    virtual void setIdentifier(int64_t identifier);
    /// @result The magnitude identifier.
    /// @throws std::runtime_error if \c hasIdentifier() is false.
    [[nodiscard]] virtual int64_t getIdentifier() const;
    /// @result True indicates the magnitude identifier was set.
    [[nodiscard]] virtual bool hasIdentifier() const noexcept;

    /// @brief The magnitude.
    /// @throws std::invalid_argument if this exceeds 11.
    virtual void setValue(double value);
    /// @result The magnitude.
    /// @throws std::runtime_error if \c hasValue() is false.
    [[nodiscard]] virtual double getValue() const;
    /// @result True indicates the magnitdue value was set.
    [[nodiscard]] virtual bool hasValue() const noexcept;

    /// @brief Sets the review status.
    virtual void setReviewStatus(ReviewStatus status) noexcept;
    /// @result Gets the review status.
    /// @throws std::runtime_error if \c hasReviewStatus() is false.
    [[nodiscard]] virtual ReviewStatus getReviewStatus() const;
    /// @result True indicates the review status was set.
    [[nodiscard]] virtual bool hasReviewStatus() const noexcept;

    /// @brief Marks this magnitude as the preferred magnitude.
    void setIsPreferred() noexcept;;
    /// @brief Marks this magnitude as not preferred and should be considered
    ///        inferior (for whatever reason) to the preferred magnitude.
    void setNotPreferred() noexcept; 
    /// @result True indicates this magnitude is the preferred magnitude.
    /// @note By default this is true in this application.
    [[nodiscard]] bool isPreferred() const noexcept;

    /// @result The magnitude type.
    [[nodiscard]] virtual Type getType() const noexcept = 0;

    /// @result A deep copy of this magnitude that preserves its derived type.
    /// @note This is the polymorphic (virtual) copy constructor used to
    ///       duplicate a magnitude when only the base class is known.
    [[nodiscard]] virtual std::unique_ptr<IMagnitude> clone() const = 0;

    /// @brief Destructor.
    virtual ~IMagnitude();
    /// @brief Copy assignment.
    IMagnitude& operator=(const IMagnitude &magnitude);
    /// @brief Move assignment.
    IMagnitude& operator=(IMagnitude &&mangnitude) noexcept;
private:
    class IMagnitudeImpl;
    std::unique_ptr<IMagnitudeImpl> pImpl;
};
}
#endif