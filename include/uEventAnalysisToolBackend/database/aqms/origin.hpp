#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_ORIGIN_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_ORIGIN_HPP 
#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>
namespace UEventAnalysisToolBackend::Database::AQMS
{
 class Arrival;
}

namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @class A simplified container for defining the when and where of an event.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class Origin
{
public:
    /// @brief The geographic type.
    enum class GeographicType
    {
        Local,      /*<! This is an event within the authoratative boundary. */ 
        Regional,   /*!< This is near'ish the authoratative boundary but not in.  
                         Think like up to 10 epicentral degrees. */
        Teleseismic /*!< This a teleseism - this is poorly defined in that it is further than regional.
                         Think like past 10 epicentral degrees but really more than 30 epicentral degrees. */
    };
    /// @brief Sets the review status.
    enum class ReviewStatus
    {
        Automatic,   /*!< This is fresh from Earthworm and has not been reviewed. */
        Cancelled,   /*!< The event corresponds to something extraneous to the mission like a large quarry blast or teleseism - why is this here and not with the event class?  Who knows?. */
        Human,       /*!< A human has reviewed and published this event and is subject to further review. */
        Finalized,   /*!< This really means the event was published - though it may have been finalized multiple times. */
        Incomplete   /*!< This really means the event was processed but was not published. */
    };
public:
    /// @brief Constructor.
    Origin();
    /// @brief Copy constructor.
    Origin(const Origin &origin);
    /// @brief Move constructor.
    Origin(Origin &&origin) noexcept;

    /// @brief Sets the origin identifier.
    void setIdentifier(int64_t identifier);
    /// @result The origin identifier.
    /// @throws std::runtime_error if \c hasIdentifier() is false.
    [[nodiscard]] int64_t getIdentifier() const;
    /// @result True indicates the origin identifier was set.
    [[nodiscard]] bool hasIdentifier() const noexcept;

    /// @brief Sets the latitude in degrees.
    /// @throws std::invalid_argument if this is not in the range [-90,90].
    void setLatitude(double latitude);
    /// @result The latitude in degrees.
    /// @throws std::runtime_error if \c hasLatitude() is false.
    [[nodiscard]] double getLatitude() const;
    /// @result True indicates the latitude was set.
    [[nodiscard]] bool hasLatitude() const noexcept;

    /// @brief Sets the longitude in degrees.
    /// @note This will make a best effort to convert the longitude to [0,360)
    ///       degrees.
    void setLongitude(double longitude);
    /// @result The longitude in degrees.
    /// @throws std::runtime_error if \c hasLongitude() is false.
    [[nodiscard]] double getLongitude() const;
    /// @result True indicates the longitude was set.
    [[nodiscard]] bool hasLongitude() const noexcept;

    /// @brief Sets the depth in meters.
    /// @throws std::invalid_argument if the depth is less than -8600 m or 
    ///         greater than 800000 m.
    void setDepth(double depth);
    /// @result The depth in meters.
    /// @throws std::runtime_error if \c hasDepth() is false.
    [[nodiscard]] double getDepth() const;
    /// @result True indicates the depth was set.
    [[nodiscard]] bool hasDepth() const noexcept;

    /// @brief Sets the origin time (UTC).
    void setTime(const std::chrono::nanoseconds &time);
    /// @result The origin time.
    /// @throws std::runtime_error if \c hasTime() is false.
    [[nodiscard]] std::chrono::nanoseconds getTime() const;
    /// @result True indicates the origin time was set.
    [[nodiscard]] bool hasTime() const noexcept;
 
    /// @brief Sets the arrivals.
    void setArrivals(const std::vector<Arrival> &arrivals);
    /// @result The arrivals that define this origin.
    [[nodiscard]] std::vector<Arrival> getArrivals() const noexcept;

    /// @brief Sets the geographic type.
    void setGeographicType(GeographicType type) noexcept;
    /// @result The geographic type.
    /// @throws std::runtime_error if \c hasGeographicType() is false.
    [[nodiscard]] GeographicType getGeographicType() const;
    /// @result True indicates the geographic type was set.
    [[nodiscard]] bool hasGeographicType() const noexcept;

    /// @brief Sets the review status.
    void setReviewStatus(ReviewStatus status) noexcept;
    /// @result Gets the review status.
    /// @throws std::runtime_error if \c hasReviewStatus() is false.
    [[nodiscard]] ReviewStatus getReviewStatus() const;
    /// @result True indicates the review status was set.
    [[nodiscard]] bool hasReviewStatus() const noexcept;

    /// @brief Marks this origin as the preferred origin.
    void setIsPreferred() noexcept;;
    /// @brief Marks this origin as not preferred and should be considered
    ///        inferior (for whatever reason) to the preferred origin.
    void setNotPreferred() noexcept; 
    /// @result True indicates this origin is the preferred origin.
    /// @note By default this is true in this application.
    [[nodiscard]] bool isPreferred() const noexcept;

    /// @brief Destructor.
    ~Origin();
    /// @brief Copy constructor. 
    Origin &operator=(const Origin &origin);
    /// @brief Move constructor.
    Origin &operator=(Origin &&origin) noexcept;
private:
    class OriginImpl;
    std::unique_ptr<OriginImpl> pImpl;
};
}
#endif
