#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include "uEventAnalysisToolBackend/database/aqms/streamIdentifier.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

class StreamIdentifier::StreamIdentifierImpl
{
public:
    std::string mNetwork;
    std::string mStation;
    std::string mChannel;
    std::string mLocationCode;
    bool mHasNetwork{false};
    bool mHasStation{false};
    bool mHasChannel{false};
    bool mHasLocationCode{false};
};

/// Constructor
StreamIdentifier::StreamIdentifier() :
    pImpl(std::make_unique<StreamIdentifierImpl> ())
{
}

/// Copy constructor
StreamIdentifier::StreamIdentifier(const StreamIdentifier &identifier)
{
    *this = identifier;
}

/// Move constructor
StreamIdentifier::StreamIdentifier(StreamIdentifier &&identifier) noexcept
{
    *this = std::move(identifier);
}

/// Copy assignment
StreamIdentifier&
StreamIdentifier::operator=(const StreamIdentifier &identifier)
{
    if (&identifier == this){return *this;}
    pImpl = std::make_unique<StreamIdentifierImpl> (*identifier.pImpl);
    return *this;
}

/// Move assignment
StreamIdentifier&
StreamIdentifier::operator=(StreamIdentifier &&identifier) noexcept
{
    if (&identifier == this){return *this;}
    pImpl = std::move(identifier.pImpl);
    return *this;
}

/// Destructor
StreamIdentifier::~StreamIdentifier() = default;

/// Network
void StreamIdentifier::setNetwork(const std::string &network)
{
    if (network.empty())
    {
        throw std::invalid_argument("Network is empty");
    }
    pImpl->mNetwork = network;
    pImpl->mHasNetwork = true;
}

std::string StreamIdentifier::getNetwork() const
{
    if (!hasNetwork()){throw std::runtime_error("Network not set");}
    return pImpl->mNetwork;
}

bool StreamIdentifier::hasNetwork() const noexcept
{
    return pImpl->mHasNetwork;
}

/// Station
void StreamIdentifier::setStation(const std::string &station)
{
    if (station.empty())
    {
        throw std::invalid_argument("Station is empty");
    }
    pImpl->mStation = station;
    pImpl->mHasStation = true;
}

std::string StreamIdentifier::getStation() const
{
    if (!hasStation()){throw std::runtime_error("Station not set");}
    return pImpl->mStation;
}

bool StreamIdentifier::hasStation() const noexcept
{
    return pImpl->mHasStation;
}

/// Channel
void StreamIdentifier::setChannel(const std::string &channel)
{
    if (channel.empty())
    {
        throw std::invalid_argument("Channel is empty");
    }
    pImpl->mChannel = channel;
    pImpl->mHasChannel = true;
}

std::string StreamIdentifier::getChannel() const
{
    if (!hasChannel()){throw std::runtime_error("Channel not set");}
    return pImpl->mChannel;
}

bool StreamIdentifier::hasChannel() const noexcept
{
    return pImpl->mHasChannel;
}

/// Location code - note this may legitimately be an empty string (e.g., "--").
void StreamIdentifier::setLocationCode(const std::string &locationCode)
{
    pImpl->mLocationCode = locationCode;
    pImpl->mHasLocationCode = true;
}

std::string StreamIdentifier::getLocationCode() const
{
    if (!hasLocationCode()){throw std::runtime_error("Location code not set");}
    return pImpl->mLocationCode;
}

bool StreamIdentifier::hasLocationCode() const noexcept
{
    return pImpl->mHasLocationCode;
}