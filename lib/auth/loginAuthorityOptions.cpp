#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "uEventAnalysisToolBackend/auth/loginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/database/credentials.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class LoginAuthorityOptions::LoginAuthorityOptionsImpl
{
public:
    UEventAnalysisToolBackend::Database::Credentials mDatabaseCredentials;
    Password::HasherOptions mPasswordHasherOptions;
    std::pair<std::string, std::string> mKeyPair;
    std::string mIssuer;
    std::chrono::seconds mTimeToLive{0};
    Algorithm mAlgorithm;
    bool mHasDatabaseCredentials{false};
    bool mHasKeyPairAndAlgorithm{false};
    bool mHasTimeToLive{false};
};

/// Constructor
LoginAuthorityOptions::LoginAuthorityOptions() :
    pImpl(std::make_unique<LoginAuthorityOptionsImpl> ())
{
}

/// Copy constructor
LoginAuthorityOptions::LoginAuthorityOptions(
    const LoginAuthorityOptions &options)
{
    *this = options;
}

/// Move constructor
LoginAuthorityOptions::LoginAuthorityOptions(
    LoginAuthorityOptions &&options) noexcept
{
    *this = std::move(options);
}

/// Copy assignment
LoginAuthorityOptions 
&LoginAuthorityOptions::operator=(const LoginAuthorityOptions &options)
{
    if (&options == this){return *this;}
    pImpl = std::make_unique<LoginAuthorityOptionsImpl> (*options.pImpl);
    return *this;
}

/// Move assignment
LoginAuthorityOptions 
&LoginAuthorityOptions::operator=(LoginAuthorityOptions &&options) noexcept
{
    if (&options == this){return *this;}
    pImpl = std::move(options.pImpl);
    return *this;
}

/// Destructor
LoginAuthorityOptions::~LoginAuthorityOptions() = default;

/// Time-to-live
void LoginAuthorityOptions::setTimeToLive(
    const std::chrono::seconds &timeToLive)
{
    if (timeToLive <= std::chrono::seconds {0})
    {   
        throw std::invalid_argument("Token time-to-live must be positive");
    }   
    pImpl->mTimeToLive = timeToLive;
    pImpl->mHasTimeToLive = true;
}

std::chrono::seconds LoginAuthorityOptions::getTimeToLive() const
{
    if (!hasTimeToLive())
    {
        throw std::runtime_error("Token time-to-live not set");
    }
    return pImpl->mTimeToLive;
}

bool LoginAuthorityOptions::hasTimeToLive() const noexcept
{
    return pImpl->mHasTimeToLive;
}

/// Creds
void LoginAuthorityOptions::setDatabaseCredentials(
    const UEventAnalysisToolBackend::Database::Credentials &credentials)
{
    if (!credentials.hasUser())
    {   
        throw std::invalid_argument("User not set");
    }   
    if (!credentials.hasPassword())
    {   
        throw std::invalid_argument("Password not set");
    }   
    if (!credentials.hasDatabaseName())
    {   
        throw std::invalid_argument("Database name not set");
    }   
    pImpl->mDatabaseCredentials = credentials;
    pImpl->mHasDatabaseCredentials = true;
}

UEventAnalysisToolBackend::Database::Credentials 
LoginAuthorityOptions::getDatabaseCredentials() const
{
    if (!hasDatabaseCredentials())
    {
        throw std::runtime_error("Credentials not set");
    }
    return pImpl->mDatabaseCredentials;
}

bool LoginAuthorityOptions::hasDatabaseCredentials() const noexcept
{
    return pImpl->mHasDatabaseCredentials;
}

/// Password hasher options
void LoginAuthorityOptions::setPasswordHasherOptions(
    const Password::HasherOptions &options)
{
    pImpl->mPasswordHasherOptions = options;
}

Password::HasherOptions
LoginAuthorityOptions::getPasswordHasherOptions() const noexcept
{
    return pImpl->mPasswordHasherOptions;
}

/// Key pair
void LoginAuthorityOptions::setKeyPairAndAlgorithm(
    const std::pair<std::string, std::string> &publicAndPrivateKey,
    const Algorithm algorithm)
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
    pImpl->mAlgorithm = algorithm;
    pImpl->mHasKeyPairAndAlgorithm = true;
}

std::pair<std::string, std::string> LoginAuthorityOptions::getKeyPair() const
{
    if (!hasKeyPairAndAlgorithm())
    {
        throw std::runtime_error("Key pair not set");
    }
    return pImpl->mKeyPair;
}

LoginAuthorityOptions::Algorithm LoginAuthorityOptions::getAlgorithm() const
{
    if (!hasKeyPairAndAlgorithm())
    {   
        throw std::runtime_error("Signing algorithm not set");
    }
    return pImpl->mAlgorithm;
}


bool LoginAuthorityOptions::hasKeyPairAndAlgorithm() const noexcept
{
    return pImpl->mHasKeyPairAndAlgorithm;
}

/// Issuer
void LoginAuthorityOptions::setIssuer(const std::string &issuer)
{
    if (issuer.empty())
    {
        throw std::invalid_argument("Issuer is empty");
    }
    pImpl->mIssuer = issuer;
}

std::string LoginAuthorityOptions::getIssuer() const
{
    if (!hasIssuer())
    {
        throw std::runtime_error("Issuer not set");
    }
   return  pImpl->mIssuer;
}

bool LoginAuthorityOptions::hasIssuer() const noexcept
{
    return !pImpl->mIssuer.empty();
}

///--------------------------------------------------------------------------///
///                         Build from ini file                              ///
///--------------------------------------------------------------------------///
namespace
{

[[nodiscard]] std::string trim(const std::string &text)
{
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos){return std::string {};}
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

/// NOLINTBEGIN(bugprone-easily-swappable-parameters)
void throwIfKeysAreIdentical(const std::string &publicKey,
                             const std::string &privateKey,
                             const std::string &source)
/// NOLINTEND(bugprone-easily-swappable-parameters)
{   
    if (::trim(publicKey) == ::trim(privateKey))
    {
        throw std::invalid_argument(
            "The public and private key in " + source + " are the same "
            "value - one of them has been pasted over the other.  The "
            "public key cannot sign and the private key cannot be "
            "published; they are different keys.");
    }
}

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

}

LoginAuthorityOptions LoginAuthorityOptions::fromInitializationFile(
    const std::filesystem::path &iniFile,
    const std::string &sectionIn,
    const std::chrono::minutes &defaultTokenTimeToLive,
    const std::string &defaultIssuer)
{
    if (defaultTokenTimeToLive.count() <= 0)
    {
        throw std::invalid_argument("Default token TTL is not positive");
    }
    if (defaultIssuer.empty())
    {
        throw std::invalid_argument("Deafult issuer is empty");
    }
    if (!std::filesystem::exists(iniFile))
    {
        throw std::invalid_argument("Initialization " + std::string{iniFile}
                                  + " file does not exist");
    }
    // Get the credentials and hasher to build the database optins
    auto credentials
        = UEventAnalysisToolBackend::Database::Credentials
             ::fromInitializationFile(iniFile, sectionIn);

    auto hasherOptions
        = Password::HasherOptions::fromInitializationFile(iniFile, sectionIn);

    // Make sure section ends with . so we can find stuff
    auto section = sectionIn;
    if (!section.empty() && section.back() != '.'){section.append(".");}

    LoginAuthorityOptions result;
    result.setDatabaseCredentials(credentials);
    result.setPasswordHasherOptions(hasherOptions);

    // Parse the initialization file
    boost::property_tree::ptree propertyTree;
    boost::property_tree::ini_parser::read_ini(iniFile, propertyTree);

    auto issuer
        = propertyTree.get<std::string> (section + "jwtIssuer", defaultIssuer);
    result.setIssuer(issuer);

    int jwtTTLInMinutes
        = static_cast<int> (defaultTokenTimeToLive.count());
    jwtTTLInMinutes
        = propertyTree.get<int> (section + "jwtTimeToLiveInMinutes",
                                 jwtTTLInMinutes);
    result.setTimeToLive(std::chrono::minutes {jwtTTLInMinutes});
 
    auto jwtAlgorithm
        = propertyTree.get<std::string> (section + "jwtSignatureAlgorithm",
                                         "ed25519");
    std::transform(jwtAlgorithm.begin(), jwtAlgorithm.end(),
                   jwtAlgorithm.begin(), ::tolower);
    bool needKeys{false};
    auto algorithm{LoginAuthorityOptions::Algorithm::EdDSA25519};
    if (jwtAlgorithm == "unsigned")
    {
        throw std::invalid_argument("Cannot used an unsigned algorithm");
    }   
    else if (jwtAlgorithm == "ed25519" || jwtAlgorithm == "eddsa25519")
    {
        algorithm = LoginAuthorityOptions::Algorithm::EdDSA25519;
        needKeys = true;
    }
    else
    {
        throw std::runtime_error("Unhandled jwt signature algorithm "
                               + jwtAlgorithm);
    }

    if (needKeys)
    {   
        auto publicKey
           = propertyTree.get_optional<std::string> (section + "jwtPublicKey");
        auto privateKey
           = propertyTree.get_optional<std::string> (section + "jwtPrivateKey");
        if (publicKey && privateKey)
        {
            if (publicKey->empty())
            {
                throw std::invalid_argument("jwtPublicKey is empty");
            }
            if (privateKey->empty())
            {
                throw std::invalid_argument("jwtPrivateKey is empty");
            }
            ::throwIfKeysAreIdentical(*publicKey, *privateKey,
                                      "jwtPublicKey and jwtPrivateKey");
            auto publicKeyText
                 = "-----BEGIN PUBLIC KEY-----\n"
                 + *publicKey + "\n"
                 + "-----END PUBLIC KEY-----";
            auto privateKeyText
                 = "\n-----BEGIN PRIVATE KEY-----\n"
                 + *privateKey + "\n"
                 + "-----END PRIVATE KEY-----";
            result.setKeyPairAndAlgorithm(
                 std::pair {publicKeyText, privateKeyText}, algorithm);
        }
        else
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
            ::throwIfKeysAreIdentical(publicKeyText, privateKeyText,
                                      "jwtPublicKeyFile (" + publicKeyFile
                                    + ") and jwtPrivateKeyFile ("
                                    + privateKeyFile + ")");
            result.setKeyPairAndAlgorithm(
                std::pair {publicKeyText, privateKeyText}, algorithm);
       }
    }
    return result;
}
