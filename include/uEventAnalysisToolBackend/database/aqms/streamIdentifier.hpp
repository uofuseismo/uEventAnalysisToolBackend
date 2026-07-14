#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_STREAM_IDENTIFIER_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_DATABASE_AQMS_STREAM_IDENTIFIER_HPP
#include <memory>
#include <string>
namespace UEventAnalysisToolBackend::Database::AQMS
{
/// @brief Convenience container to holds the Network, Station,
///        Channel, and Location Code.
/// @copyright Ben Baker (University of Utah) distributed under the MIT NO AI
///            license.
class StreamIdentifier
{
public:
    /// @brief Constructor.
    StreamIdentifier();
    /// @brief Copy constructor.
    StreamIdentifier(const StreamIdentifier &identifier);
    /// @brief Move constructor.
    StreamIdentifier(StreamIdentifier &&identifier) noexcept;

    /// @brief Sets the network code - e.g., UU.
    void setNetwork(const std::string &network);
    /// @brief The network code.
    /// @throws std::runtime_error if \c hasNetwork() is false.
    [[nodiscard]] std::string getNetwork() const;
    /// @result True indicates the network was set.
    [[nodiscard]] bool hasNetwork() const noexcept;

    /// @brief Sets the station code - e.g., CTU.
    void setStation(const std::string &station);
    /// @brief The station code.
    /// @throws std::runtime_error if \c hasStation() is false.
    [[nodiscard]] std::string getStation() const;
    /// @result True indicates the station was set.
    [[nodiscard]] bool hasStation() const noexcept;

    /// @brief Sets the channel code - e.g., HHZ.
    void setChannel(const std::string &channel);
    /// @brief The channel code.
    /// @throws std::runtime_error if \c hasChannel() is false.
    [[nodiscard]] std::string getChannel() const;
    /// @result True indicates the channel was set.
    [[nodiscard]] bool hasChannel() const noexcept;

    /// @brief Sets the location code - e.g., "01" or "--" or, even, "".
    void setLocationCode(const std::string &locationCode);
    /// @brief The location code.
    /// @throws std::runtime_error if \c hasLocationCode() is false.
    [[nodiscard]] std::string getLocationCode() const;
    /// @result True indicates the location code was set.
    [[nodiscard]] bool hasLocationCode() const noexcept;


    /// @brief Destructor.
    ~StreamIdentifier();
    /// @brief Copy assignment.
    StreamIdentifier &operator=(const StreamIdentifier &identifier);
    /// @brief Move assignment.
    StreamIdentifier &operator=(StreamIdentifier &&identifier) noexcept;
private:
    class StreamIdentifierImpl;
    std::unique_ptr<StreamIdentifierImpl> pImpl;
};
}
#endif
