#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class TokenVerifierOptions::TokenVerifierOptionsImpl
{
public:
    Algorithm mAlgorithm;
    std::string mIssuer;
    std::string mPublicKey;
    std::chrono::seconds mClockLeeway{0};
    bool mHasPublicKeyAndAlgorithm{false};
};

/// Constructor
TokenVerifierOptions::TokenVerifierOptions() :
    pImpl(std::make_unique<TokenVerifierOptionsImpl> ())
{
}

/// Copy constructor
TokenVerifierOptions::TokenVerifierOptions(
    const TokenVerifierOptions &options)
{
    *this = options;
}

/// Move constructor
TokenVerifierOptions::TokenVerifierOptions(
    TokenVerifierOptions &&options) noexcept
{
    *this = std::move(options);
}

/// Copy assignment
TokenVerifierOptions&
TokenVerifierOptions::operator=(const TokenVerifierOptions &options)
{
    if (&options == this){return *this;}
    pImpl = std::make_unique<TokenVerifierOptionsImpl> (*options.pImpl);
    return *this;
}

/// Move assignment
TokenVerifierOptions&
TokenVerifierOptions::operator=(TokenVerifierOptions &&options) noexcept
{
    if (&options == this){return *this;}
    pImpl = std::move(options.pImpl);
    return *this;
}

/// Destructor
TokenVerifierOptions::~TokenVerifierOptions() = default;

/// Issuer
void TokenVerifierOptions::setIssuer(const std::string &issuer)
{
    if (issuer.empty())
    {
        throw std::invalid_argument("Issuer is empty");
    }
    pImpl->mIssuer = issuer;
}

std::string TokenVerifierOptions::getIssuer() const
{
    if (!hasIssuer())
    {
        throw std::runtime_error("Issuer not set");
    }
   return  pImpl->mIssuer;
}

bool TokenVerifierOptions::hasIssuer() const noexcept
{
    return !pImpl->mIssuer.empty();
}

/// Public key
void TokenVerifierOptions::setPublicKeyAndAlgorithm(
    const std::string &publicKey, const Algorithm algorithm)
{
    if (publicKey.empty())
    {
        throw std::invalid_argument("Public key is empty");
    }
    pImpl->mPublicKey = publicKey;
    pImpl->mAlgorithm = algorithm;
    pImpl->mHasPublicKeyAndAlgorithm = true;
}

std::string TokenVerifierOptions::getPublicKey() const
{
    if (!hasPublicKeyAndAlgorithm())
    {
        throw std::runtime_error("Public key not set");
    }
    return pImpl->mPublicKey;
}

TokenVerifierOptions::Algorithm TokenVerifierOptions::getAlgorithm() const
{
    if (!hasPublicKeyAndAlgorithm())
    {
        throw std::runtime_error("Algorithm not set");
    }
    return pImpl->mAlgorithm;
}

bool TokenVerifierOptions::hasPublicKeyAndAlgorithm() const noexcept
{
    return pImpl->mHasPublicKeyAndAlgorithm;
}

/// Leeway
void TokenVerifierOptions::setClockLeeway(
    const std::chrono::seconds &leeway)
{
    if (leeway.count() < 0)
    {
        throw std::invalid_argument("Leeway cannot be negative");
    }
    pImpl->mClockLeeway = leeway;
}

std::chrono::seconds TokenVerifierOptions::getClockLeeway() const noexcept
{
    return pImpl->mClockLeeway;
}

