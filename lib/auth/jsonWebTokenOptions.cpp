#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include "uEventAnalysisToolBackend/auth/jsonWebTokenOptions.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class JSONWebTokenOptions::JSONWebTokenOptionsImpl
{
public:
    std::pair<std::string, std::string> mKeyPair;
    std::chrono::seconds mTimeToLive{std::chrono::minutes {15}};
    Algorithm mAlgorithm{Algorithm::EdDSA25519};
    bool mHasKeyPair{false};
};

/// Constructor
JSONWebTokenOptions::JSONWebTokenOptions() :
    pImpl(std::make_unique<JSONWebTokenOptionsImpl> ())
{
}

/// Copy constructor
JSONWebTokenOptions::JSONWebTokenOptions(const JSONWebTokenOptions &options)
{
    *this = options;
}

/// Move constructor
JSONWebTokenOptions::JSONWebTokenOptions(JSONWebTokenOptions &&options) noexcept
{
    *this = std::move(options);
}

/// Copy assignment
JSONWebTokenOptions&
JSONWebTokenOptions::operator=(const JSONWebTokenOptions &options)
{
    if (&options == this){return *this;}
    pImpl = std::make_unique<JSONWebTokenOptionsImpl> (*options.pImpl);
    return *this;
}

/// Move assignment
JSONWebTokenOptions&
JSONWebTokenOptions::operator=(JSONWebTokenOptions &&options) noexcept
{
    if (&options == this){return *this;}
    pImpl = std::move(options.pImpl);
    return *this;
}

/// Destructor
JSONWebTokenOptions::~JSONWebTokenOptions() = default;

/// Time-to-live
void JSONWebTokenOptions::setTimeToLive(const std::chrono::seconds &timeToLive)
{
    if (timeToLive <= std::chrono::seconds {0})
    {
        throw std::invalid_argument("Token time-to-live must be positive");
    }
    pImpl->mTimeToLive = timeToLive;
}

std::chrono::seconds JSONWebTokenOptions::getTimeToLive() const noexcept
{
    return pImpl->mTimeToLive;
}

/// Algorithm
void JSONWebTokenOptions::setAlgorithm(const Algorithm algorithm) noexcept
{
    pImpl->mAlgorithm = algorithm;
}

JSONWebTokenOptions::Algorithm JSONWebTokenOptions::getAlgorithm() const noexcept
{
    return pImpl->mAlgorithm;
}

/// Key pair
void JSONWebTokenOptions::setKeyPair(
    const std::pair<std::string, std::string> &publicAndPrivateKey)
{
    if (publicAndPrivateKey.first.empty())
    {
        throw std::invalid_argument("Public key is empty");
    }
    if (publicAndPrivateKey.second.empty())
    {
        throw std::invalid_argument("Private key is empty");
    }
    if (publicAndPrivateKey.first == publicAndPrivateKey.second)
    {
        throw std::invalid_argument("Public key cannot match private key");
    }
    pImpl->mKeyPair = publicAndPrivateKey;
    pImpl->mHasKeyPair = true;
}

std::pair<std::string, std::string> JSONWebTokenOptions::getKeyPair() const
{
    if (!hasKeyPair()){throw std::runtime_error("Key pair not set");}
    return pImpl->mKeyPair;
}

bool JSONWebTokenOptions::hasKeyPair() const noexcept
{
    return pImpl->mHasKeyPair;
}

///--------------------------------------------------------------------------///
///                         Build from ini file                              ///
///--------------------------------------------------------------------------///
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>

[[nodiscard]] std::string
static loadStringFromFile(const std::filesystem::path &path)
{
    std::string result;
    if (!std::filesystem::exists(path)){return result;}
    std::ifstream file(path);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open " + path.string());
    }
    std::stringstream sstr;
    sstr << file.rdbuf();
    file.close(); 
    result = sstr.str();
    return result;
}

JSONWebTokenOptions JSONWebTokenOptions::fromInitializationFile(
    const std::filesystem::path &iniFile,
    const std::string &sectionIn)
{
    if (!std::filesystem::exists(iniFile))
    {
        throw std::invalid_argument("Initialization " + std::string{iniFile}
                                  + " file does not exist");
    }   
    // Make sure section ends with . so we can find stuff
    auto section = sectionIn;
    if (!section.empty() && section.back() != '.'){section.append(".");}

    JSONWebTokenOptions result;

    // Parse the initialization file
    boost::property_tree::ptree propertyTree;
    boost::property_tree::ini_parser::read_ini(iniFile, propertyTree);

    
    auto jwtTTLInMinutes
        = static_cast<int> (std::chrono::duration_cast<std::chrono::minutes>
          (result.getTimeToLive()).count());
    jwtTTLInMinutes
        = propertyTree.get<int> (section + "jwtTimeToLiveInMinutes",
                                 jwtTTLInMinutes);
    result.setTimeToLive(std::chrono::minutes {jwtTTLInMinutes});
 
    auto jwtAlgorithm
        = propertyTree.get<std::string> (section + "jwtSignatureAlgorithm",
                                         "ed25519");
    std::transform(jwtAlgorithm.begin(), jwtAlgorithm.end(),
                   jwtAlgorithm.begin(), ::tolower);
    if (jwtAlgorithm == "unsigned")
    {
        result.setAlgorithm(JSONWebTokenOptions::Algorithm::Unsigned);
    }
    else if (jwtAlgorithm == "ed25519" || jwtAlgorithm == "eddsa25519")
    {
        result.setAlgorithm(JSONWebTokenOptions::Algorithm::EdDSA25519);
    }
    else
    {
        throw std::runtime_error("Unhandled jwt signature algorithm "
                               + jwtAlgorithm);
    }

    if (result.getAlgorithm() != JSONWebTokenOptions::Algorithm::Unsigned)
    {
        auto publicKeyFile
           = propertyTree.get<std::string> (section + "jwtPublicKeyFile");
        auto privateKeyFile
           = propertyTree.get<std::string> (section + "jwtPrivateKeyFile");
        if (!std::filesystem::exists(publicKeyFile))
        {
            throw std::invalid_argument("Public key file does not exist");
        }
        if (!std::filesystem::exists(privateKeyFile))
        {
            throw std::invalid_argument("Private key file does not exist"); 
        }
        auto publicKeyText = ::loadStringFromFile(publicKeyFile);
        auto privateKeyText = ::loadStringFromFile(privateKeyFile); 
        result.setKeyPair(std::pair {publicKeyText, privateKeyText});
    }
    return result;
}
