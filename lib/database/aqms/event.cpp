#include <algorithm>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>
#include "uEventAnalysisToolBackend/database/aqms/event.hpp"
#include "uEventAnalysisToolBackend/database/aqms/origin.hpp"
#include "uEventAnalysisToolBackend/database/aqms/magnitude.hpp"

using namespace UEventAnalysisToolBackend::Database::AQMS;

namespace
{

/// @brief Deep-copies a vector of polymorphic magnitudes via clone().
std::vector<std::unique_ptr<IMagnitude>>
cloneMagnitudes(const std::vector<std::unique_ptr<IMagnitude>> &magnitudes)
{
    std::vector<std::unique_ptr<IMagnitude>> result;
    result.reserve(magnitudes.size());
    for (const auto &magnitude : magnitudes)
    {
        result.push_back(magnitude ? magnitude->clone() : nullptr);
    }
    return result;
}

}

class Event::EventImpl
{
public:
    EventImpl() = default;
    EventImpl(const EventImpl &impl){*this = impl;}
    EventImpl(EventImpl &&impl) noexcept = default;
    /// The magnitudes are held by unique_ptr (move-only) so the copy must
    /// clone each element to preserve value semantics for Event.
    EventImpl& operator=(const EventImpl &impl)
    {
        if (&impl == this){return *this;}
        mOrigins = impl.mOrigins;
        mMagnitudes = cloneMagnitudes(impl.mMagnitudes);
        mIdentifier = impl.mIdentifier;
        mEventType = impl.mEventType;
        mHasIdentifier = impl.mHasIdentifier;
        mHasEventType = impl.mHasEventType;
        return *this;
    }
    EventImpl& operator=(EventImpl &&impl) noexcept = default;
    ~EventImpl() = default;

    std::vector<Origin> mOrigins;
    std::vector<std::unique_ptr<IMagnitude>> mMagnitudes;
    int64_t mIdentifier{0};
    EventType mEventType{EventType::Unknown};
    bool mHasIdentifier{false};
    bool mHasEventType{false};
};

/// Constructor
Event::Event() :
    pImpl(std::make_unique<EventImpl> ())
{
}

/// Copy constructor
Event::Event(const Event &event)
{
    *this = event;
}

/// Move constructor
Event::Event(Event &&event) noexcept
{
    *this = std::move(event);
}

/// Copy assignment
Event& Event::operator=(const Event &event)
{
    if (&event == this){return *this;}
    pImpl = std::make_unique<EventImpl> (*event.pImpl);
    return *this;
}

/// Move assignment
Event& Event::operator=(Event &&event) noexcept
{
    if (&event == this){return *this;}
    pImpl = std::move(event.pImpl);
    return *this;
}

/// Destructor
Event::~Event() = default;

/// Identifier
void Event::setIdentifier(const int64_t identifier)
{
    pImpl->mIdentifier = identifier;
    pImpl->mHasIdentifier = true;
}

int64_t Event::getIdentifier() const
{
    if (!hasIdentifier()){throw std::runtime_error("Event identifier not set");}
    return pImpl->mIdentifier;
}

bool Event::hasIdentifier() const noexcept
{
    return pImpl->mHasIdentifier;
}

/// Origins
void Event::setOrigins(const std::vector<Origin> &origins)
{
    if (origins.empty())
    {
        throw std::invalid_argument("There must be at least one origin");
    }
    for (const auto &origin : origins)
    {
        if (!origin.hasLatitude())
        {
            throw std::invalid_argument("An origin is missing its latitude");
        }
        if (!origin.hasLongitude())
        {
            throw std::invalid_argument("An origin is missing its longitude");
        }
        if (!origin.hasDepth())
        {
            throw std::invalid_argument("An origin is missing its depth");
        }
        if (!origin.hasTime())
        {
            throw std::invalid_argument("An origin is missing its time");
        }
    }
    auto nPreferred = std::count_if(origins.begin(), origins.end(),
                                    [](const Origin &origin)
                                    {
                                        return origin.isPreferred();
                                    });
    if (nPreferred != 1)
    {
        throw std::invalid_argument(
            "There must be exactly one preferred origin");
    }
    pImpl->mOrigins = origins;
}

bool Event::hasOrigins() const noexcept
{
    return !pImpl->mOrigins.empty();
}

Origin Event::getPreferredOrigin() const
{
    if (!hasOrigins()){throw std::runtime_error("Origins not set");}
    for (const auto &origin : pImpl->mOrigins)
    {
        if (origin.isPreferred()){return origin;}
    }
    // setOrigins guarantees a preferred origin exists, so this is unreachable
    // in practice.
    throw std::runtime_error("No preferred origin");
}

std::vector<Origin> Event::getOrigins() const
{
    if (!hasOrigins()){throw std::runtime_error("Origins not set");}
    return pImpl->mOrigins;
}

/// Magnitudes
void Event::setMagnitudes(
    const std::vector<std::unique_ptr<IMagnitude>> &magnitudes)
{
    if (magnitudes.empty())
    {
        throw std::invalid_argument("There must be at least one magnitude");
    }
    std::vector<IMagnitude::Type> seenTypes;
    seenTypes.reserve(magnitudes.size());
    for (const auto &magnitude : magnitudes)
    {
        if (magnitude == nullptr)
        {
            throw std::invalid_argument("A magnitude is null");
        }
        auto type = magnitude->getType();
        if (std::find(seenTypes.begin(), seenTypes.end(), type)
            != seenTypes.end())
        {
            throw std::invalid_argument("Two magnitudes share the same type");
        }
        seenTypes.push_back(type);
    }
    auto nPreferred = std::count_if(magnitudes.begin(), magnitudes.end(),
                                    [](const std::unique_ptr<IMagnitude> &m)
                                    {
                                        return m->isPreferred();
                                    });
    if (nPreferred != 1)
    {
        throw std::invalid_argument(
            "There must be exactly one preferred magnitude");
    }
    pImpl->mMagnitudes = cloneMagnitudes(magnitudes);
}

bool Event::hasMagnitudes() const noexcept
{
    return !pImpl->mMagnitudes.empty();
}

std::vector<std::unique_ptr<IMagnitude>> Event::getMagnitudes() const
{
    if (!hasMagnitudes()){throw std::runtime_error("Magnitudes not set");}
    return cloneMagnitudes(pImpl->mMagnitudes);
}

std::unique_ptr<IMagnitude> Event::getPreferredMagnitude() const
{
    if (!hasMagnitudes()){throw std::runtime_error("Magnitudes not set");}
    for (const auto &magnitude : pImpl->mMagnitudes)
    {
        if (magnitude->isPreferred()){return magnitude->clone();}
    }
    // setMagnitudes guarantees exactly one preferred magnitude, so this is
    // unreachable in practice.
    throw std::runtime_error("No preferred magnitude");
}

/// Event type
void Event::setEventType(const EventType type) noexcept
{
    pImpl->mEventType = type;
    pImpl->mHasEventType = true;
}

Event::EventType Event::getEventType() const
{
    if (!hasEventType()){throw std::runtime_error("Event type not set");}
    return pImpl->mEventType;
}

bool Event::hasEventType() const noexcept
{
    return pImpl->mHasEventType;
}