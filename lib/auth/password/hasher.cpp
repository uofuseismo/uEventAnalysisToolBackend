#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <sodium/crypto_pwhash.h>
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth::Password;

namespace
{
int toOpsLimit(const HasherOptions::OperationsLimit &limit)
{
    int operationsLimit{crypto_pwhash_OPSLIMIT_INTERACTIVE};
    if (limit == HasherOptions::OperationsLimit::Interactive)
    {
        operationsLimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    }
    else if (limit == HasherOptions::OperationsLimit::Moderate)
    {
        operationsLimit = crypto_pwhash_OPSLIMIT_MODERATE;
    }
    else if (limit == HasherOptions::OperationsLimit::Sensitive)
    {
        operationsLimit = crypto_pwhash_OPSLIMIT_SENSITIVE;
    }
    else
    {
        // Should never happen
        throw std::runtime_error("Unhandled opslimit");
    }
    return operationsLimit;
}

}

class Hasher::HasherImpl
{
public:
    explicit HasherImpl(const HasherOptions &options) :
        mOptions(options)
    {
    }
//private:
    HasherOptions mOptions;
};

/// Constructor
Hasher::Hasher(const HasherOptions &options) :
    pImpl(std::make_unique<HasherImpl> (options))
{
}

// Copy assignment
Hasher::Hasher(const Hasher &hasher)
{
    *this = hasher;
}

/// Move assignment
Hasher::Hasher(Hasher &&hasher) noexcept
{
    *this = std::move(hasher);
}

/// Copy assignment
Hasher& Hasher::operator=(const Hasher &hasher)
{
    if (&hasher == this){return *this;}
    pImpl = std::make_unique<HasherImpl> (*hasher.pImpl);
    return *this;
}

/// Move assignment
Hasher& Hasher::operator=(Hasher &&hasher) noexcept
{
    if (&hasher == this){return *this;}
    pImpl = std::move(hasher.pImpl);
    return *this;
}

/// Destructor
Hasher::~Hasher() = default;

/// Hash the password
std::string Hasher::hash(const std::string &password) const
{
    std::string hashedPassword;
    hashedPassword.resize(crypto_pwhash_STRBYTES);
    auto operationsLimit = ::toOpsLimit(pImpl->mOptions.getOperationsLimit());
    auto memoryLimit = pImpl->mOptions.getMemoryLimitInBytes();
    if (crypto_pwhash_str(hashedPassword.data(),
                          password.c_str(),
                          password.length(),
                          operationsLimit,
                          memoryLimit) != 0)
    {
        throw std::runtime_error("crypto_pwhash_str out of memory"); 
    }
    // Remove the NULL-terminator
    hashedPassword.resize(std::strlen(hashedPassword.c_str()));
    return hashedPassword;
}

/// Password needs re-hash?
bool Hasher::needsRehash(const std::string &encodedHash) const
{
    auto operationsLimit = ::toOpsLimit(pImpl->mOptions.getOperationsLimit());
    auto memoryLimit = pImpl->mOptions.getMemoryLimitInBytes();
    auto result = crypto_pwhash_str_needs_rehash(encodedHash.c_str(),
                                                 operationsLimit,
                                                 memoryLimit);
    if (result == 0)
    {
        return false;
    }
    else if (result == 1)
    {
        return true;
    }
    throw std::runtime_error("Failed to parse hash");
}

