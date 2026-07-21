#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_EVENT_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_EVENT_HPP 
#include <cstdint>
#include <memory>
#include <vector>
namespace UEventAnalysisToolBackend::Database::AQMS
{
 class IMagnitude;
 class Origin;
}
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @brief A simplified seismic event.
class Event
{
public:
    enum class EventType
    {
        Avalanche,      /*!< An avalanche. */
        Collapse,       /*!< A mine collapse event. */
        Earthquake,     /*!< A regular, old earthquake. */
        Explosion,      /*!< Some type of explosion that isn't a quarry blast. */
        Landslide,      /*!< Landslide. */
        MiningInduced,  /*!< Mining induced event. */
        NuclearTest,    /*!< A nuclear test - Utah is known for its sunsets! */
        QuarryBlast,    /*!< A quarry blast. */
        Sonic,          /*!< A sonic event. */
        SubnetTrigger,  /*<! This is an earthworm artifact. */
        Unknown         /*!< Catch all */
    };
public:
    /// @brief Constructor.
    Event(); 
    /// @brief Copy constructor.
    Event(const Event &event);
    /// @brief Move constructor.
    Event(Event &&event) noexcept;

    /// @brief Sets the event identifier.
    void setIdentifier(int64_t identifier);
    /// @result The event identifier.
    /// @throws std::runtime_error if \c hasIdentifier() is false.
    [[nodiscard]] int64_t getIdentifier() const;
    /// @result True indicates the event identifier was set.
    [[nodiscard]] bool hasIdentifier() const noexcept;

    /// @brief Sets the origins.
    /// @note All origins must have required fields (e.g., latitude, longitude,
    ///       depth, time) and one and only one origin must be the preferred origin.
    void setOrigins(const std::vector<Origin> &origins);
    void setOrigins(std::vector<Origin> &&origins);
    /// @result True indicates that the origins were set.
    [[nodiscard]] bool hasOrigins() const noexcept; 
    /// @brief The preferred origin.
    /// @throws std::runtime_error if \c hasOrigins() is false.
    [[nodiscard]] Origin getPreferredOrigin() const;
    /// @brief Gets the origins.
    /// @throws std::runtime_error if \c hasOrigins() is false. 
    [[nodiscard]] std::vector<Origin> getOrigins() const; 

    /// @brief Sets the magnitudes.
    /// @note Every magnitude must have a different type and there must be
    ///       one and only one magnitude that is preferred.
    /// @throws std::invalid_argument if a magnitude is null, two magnitudes
    ///         share a type, or the number of preferred magnitudes is not one.
    void setMagnitudes(const std::vector<std::unique_ptr<IMagnitude>> &magnitudes);
    /// @result Deep copies of the magnitudes, preserving their derived types.
    /// @throws std::runtime_error if \c hasMagnitudes() is false.
    [[nodiscard]] std::vector<std::unique_ptr<IMagnitude>> getMagnitudes() const;
    /// @result A deep copy of the preferred magnitude.
    /// @throws std::runtime_error if \c hasMagnitudes() is false.
    [[nodiscard]] std::unique_ptr<IMagnitude> getPreferredMagnitude() const;
    /// @result True indicates the magnitudes were set.
    [[nodiscard]] bool hasMagnitudes() const noexcept;

    /// @brief Sets the event type.
    void setEventType(EventType type) noexcept;
    /// @result The event type.
    /// @throws std::runtime_error if \c hasEventType() is false.
    [[nodiscard]] EventType getEventType() const;
    /// @result True indicates the event type was set.
    [[nodiscard]] bool hasEventType() const noexcept;

    /// @brief Destructor.
    ~Event();
    /// @brief Copy assignment.
    Event &operator=(const Event &event);
    /// @brief Move assignment.
    Event &operator=(Event &&event) noexcept;
private:
    class EventImpl;
    std::unique_ptr<EventImpl> pImpl;
};
}
#endif
