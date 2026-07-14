#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_ARRIVAL_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_ARRIVAL_HPP
#include <cstdint>
#include <chrono>
#include <memory>
#include <optional>

namespace UEventAnalysisToolBackend::Database::AQMS
{
 class StreamIdentifier;
}

namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @brief A arrival in the AQMS database.  This is slightly merged with the
///        assocaro table.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class Arrival
{
public:
    /// @brief Defines the seismic phase.
    enum class Phase
    {
        P, /*!< P arrival. */
        S  /*!< S arrival. */
    };
    /// @brief Defines the review status.
    enum class ReviewStatus
    {
        Automatic, /*!< This is an automatically generated arrival. */
        Human      /*!< This is a human-made arrival. */
   };
public:
    /// @brief Constructor.
    Arrival();
    /// @brief Copy constructor.
    Arrival(const Arrival &arrival);
    /// @brief Move constructor.
    Arrival(Arrival &&arrival) noexcept;

    /// @brief Sets the arrival identifier.
    void setIdentifier(int64_t identifier);
    /// @brief Gets the arrival identifier.
    /// @throws std::runtime_error if \c hasIdentifier() is false.
    [[nodiscard]] int64_t getIdentifier() const;
    /// @result True indicates the arrival identifier was set.
    [[nodiscard]] bool hasIdentifier() const noexcept;

    /// @brief Sets the arrival time (UTC).
    void setTime(const std::chrono::nanoseconds &time) noexcept;
    /// @result The arrival time.
    /// @throws std::runtime_error if \c hasTime() is false.
    [[nodiscard]] std::chrono::nanoseconds getTime() const;
    /// @result True inidcates the arrival time was set.
    [[nodiscard]] bool hasTime() const noexcept;

    /// @brief Sets the phase.
    void setPhase(Phase phase) noexcept;
    /// @result Gets the phase.
    /// @throws std::runtime_error if \c hasPhase() is false.
    [[nodiscard]] Phase getPhase() const;
    /// @result True indicates the phase was set.
    [[nodiscard]] bool hasPhase() const noexcept;

    /// @brief Sets the review status.
    void setReviewStatus(ReviewStatus status) noexcept;
    /// @result Gets the review status.
    /// @throws std::runtime_error if \c hasReviewStatus() is false.
    [[nodiscard]] ReviewStatus getReviewStatus() const;
    /// @result True indicates the review status was set.
    [[nodiscard]] bool hasReviewStatus() const noexcept;

    /// @brief Sets the stream identifier on which the arrival was made.
    /// @throws std::invalid_argument if the network, station, channel,
    ///         or location code was not set.
    void setStreamIdentifier(const StreamIdentifier &identifier);
    /// @result Gets the stream identifier.
    /// @throws std::runtime_error if \c hasStreamIdentifier() is false.
    [[nodiscard]] StreamIdentifier getStreamIdentifier() const;
    /// @brief True indicates the stream identifier was set.
    [[nodiscard]] bool hasStreamIdentifier() const noexcept;

    /// @brief Sets the "quality" of the arrival - like a weight.
    ///        This will normally be 0 (worst), 0.25, 0.5, 0.75, or 1 (best).
    /// @throws std::invalid_argument if the quality is negative.
    void setQuality(double quality);
    /// @result the quality of the arrival.
    [[nodiscard]] std::optional<double> getQuality() const noexcept;

    /// @brief Sets the time residual (from the assocaro table).
    /// @param[in] residual   Note, the residual is measured in 
    ///                       observed - estimated.
    void setResidual(const std::chrono::nanoseconds &residual);
    /// @result Gets the residual.
    /// @throws std::runtime_error if \c hasResidual() is false.
    [[nodiscard]] std::chrono::nanoseconds getResidual() const; 
    /// @result True indicates the residual was set.
    [[nodiscard]] bool hasResidual() const noexcept;

    /// @brief Destructor.
    ~Arrival();
    /// @brief Copy assignment.
    Arrival& operator=(const Arrival &arrival);
    /// @brief Move assignment.
    Arrival& operator=(Arrival &&arrival) noexcept;
private:
    class ArrivalImpl;
    std::unique_ptr<ArrivalImpl> pImpl;
};
}
#endif
