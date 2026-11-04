#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_TESTING_AUTH_KEY_ASSERTION_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_TESTING_AUTH_KEY_ASSERTION_HPP
#include <array>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <sodium/core.h>
#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

// What a key-login client does: holds an Ed25519 key pair and signs
// short-lived assertions (compact JWS, alg EdDSA) with it.  Built from
// libsodium directly rather than jwt-cpp, so a test can sign things a
// well-behaved library would refuse to produce.

namespace IntegrationDatabase
{

[[nodiscard]] inline std::string
    toBase64(const unsigned char *bytes, const std::size_t length,
             const int variant)
{
    // The encoded length includes the trailing NUL libsodium writes.
    std::string encoded(sodium_base64_ENCODED_LEN(length, variant), '\0');
    sodium_bin2base64(encoded.data(), encoded.size(), bytes, length, variant);
    encoded.pop_back();
    return encoded;
}

[[nodiscard]] inline std::string toBase64Url(std::string_view text)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return toBase64(reinterpret_cast<const unsigned char *> (text.data()),
                    text.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

class KeyPair
{
public:
    KeyPair()
    {
        if (sodium_init() == -1)
        {
            throw std::runtime_error("Could not initialize libsodium");
        }
        crypto_sign_keypair(mPublicKey.data(), mSecretKey.data());
    }
    /// @result The raw public key, as the LoginWithKey request carries it.
    [[nodiscard]] std::vector<unsigned char> publicKey() const
    {
        return {mPublicKey.begin(), mPublicKey.end()};
    }
    /// @result The public key as auth.user_keys stores it.
    [[nodiscard]] std::string encodedPublicKey() const
    {
        return toBase64(mPublicKey.data(), mPublicKey.size(),
                        sodium_base64_VARIANT_ORIGINAL);
    }
    /// @result The compact JWS header.payload.signature.
    [[nodiscard]] std::string sign(const boost::json::object &header,
                                   const boost::json::object &payload) const
    {
        const auto signingInput
            = toBase64Url(boost::json::serialize(header)) + "."
            + toBase64Url(boost::json::serialize(payload));
        std::array<unsigned char, crypto_sign_BYTES> signature{};
        crypto_sign_detached(
            signature.data(), nullptr,
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<const unsigned char *> (signingInput.data()),
            signingInput.size(), mSecretKey.data());
        return signingInput + "."
             + toBase64(signature.data(), signature.size(),
                        sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    }
private:
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> mPublicKey{};
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> mSecretKey{};
};

/// @result A random jti, as a client would make one.
[[nodiscard]] inline std::string randomJti()
{
    std::array<unsigned char, 16> bytes{};
    randombytes_buf(bytes.data(), bytes.size());
    std::string hex(bytes.size()*2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), bytes.data(), bytes.size());
    hex.pop_back();
    return hex;
}

[[nodiscard]] inline boost::json::object assertionHeader()
{
    return {{"alg", "EdDSA"}, {"typ", "JWT"}};
}

/// @result The claims of a well-formed assertion, good for 30 seconds,
///         for the test to sign as is or break first.
[[nodiscard]] inline boost::json::object
    assertionPayload(const std::string &subject, const std::string &audience)
{
    const auto now
        = std::chrono::duration_cast<std::chrono::seconds>
          (std::chrono::system_clock::now().time_since_epoch()).count();
    return {{"sub", subject},
            {"aud", audience},
            {"iat", static_cast<std::int64_t> (now)},
            {"exp", static_cast<std::int64_t> (now + 30)},
            {"jti", randomJti()}};
}

}
#endif
