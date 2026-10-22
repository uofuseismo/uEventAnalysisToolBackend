#include <algorithm>
#include <cctype>
#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <grpcpp/support/status.h>
#include <grpcpp/support/string_ref.h>
#include <sodium/utils.h>
#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"

namespace
{
/// @brief Trims leading and trailing linear whitespace.
[[nodiscard]] std::string_view trim(std::string_view text) noexcept
{
    constexpr std::string_view whitespace{" \t\r\n"};
    const auto begin = text.find_first_not_of(whitespace);
    if (begin == std::string_view::npos){return std::string_view {};}
    const auto end = text.find_last_not_of(whitespace);
    return text.substr(begin, end - begin + 1);
}

[[nodiscard]] bool equalsIgnoringCase(std::string_view lhs,
                                      std::string_view rhs) noexcept
{
    return std::ranges::equal(lhs, rhs,
                              [](const char a, const char b) noexcept
                              {
                                  return std::tolower(
                                             static_cast<unsigned char> (a))
                                      == std::tolower(
                                             static_cast<unsigned char> (b));
                              });
}

[[nodiscard]] std::optional<std::string> decodeBase64(std::string_view encoded)
{
    if (encoded.empty()){return std::nullopt;}
    // 3 bytes out per 4 in, rounded up; never smaller than the true size.
    std::vector<unsigned char> decoded((encoded.size()/4 + 1)*3, 0); 
    size_t decodedLength{0};
    const char *encodedEnd{nullptr};
    const auto returnCode
        = sodium_base642bin(decoded.data(), decoded.size(),
                            encoded.data(), encoded.size(),
                            nullptr, // No characters to ignore
                            &decodedLength,
                            &encodedEnd,
                            sodium_base64_VARIANT_ORIGINAL);
    if (returnCode != 0){return std::nullopt;}
    // Trailing junk after otherwise valid base64 stops the decode
    // early rather than failing it, so check the whole input was
    // consumed.
    if (encodedEnd != encoded.data() + encoded.size()){return std::nullopt;}
    return std::string {reinterpret_cast<const char *> (decoded.data()),
                        decodedLength};
}


}

std::expected
<
   std::pair<std::string, std::string>,
   grpc::Status
> 
UEventAnalysisToolBackend::GRPC::authorizationHeaderToUserNameAndPassword(
    const grpc::string_ref &grpcHeader)
{
    const std::string_view header
    {
        grpcHeader.data(),
        grpcHeader.size()
    };
    const auto value = ::trim(header);
    if (value.empty())
    {
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "Basic credentials are absent"
            });
    }

    const auto separator = value.find_first_of(" \t");
    if (separator == std::string_view::npos)
    {
        return std::unexpected(
            grpc::Status
            {   
                grpc::StatusCode::UNAUTHENTICATED,
                "Basic credentials malformed"
            }); 
    }

    const auto scheme = value.substr(0, separator);
    if (!::equalsIgnoringCase(scheme, "Basic"))
    {
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "Only Basic credentials supported"
            });
    }

    const auto rest = ::trim(value.substr(separator + 1));
    if (rest.empty())
    {   
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "Empty user and password"
            });
    }

    const auto decoded = ::decodeBase64(rest);
    if (decoded == std::nullopt)
    {
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "Failed to decode base64 Basic credentials"
            });
    }
 
    // RFC 7617 forbids a colon in the user name
    const auto colon = decoded->find(':');
    if (colon == std::string::npos)
    {
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "User and password must be separated by colon"
            });
    }

    std::string user{decoded->substr(0, colon)};
    if (std::ranges::any_of(user,
                            [](const char c)
                            {
                                return std::iscntrl(
                                    static_cast<unsigned char> (c)) != 0;
                            }))
    {
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "User name cannot contain control characters"
            });
    }
    std::string password{decoded->substr(colon + 1)}; 
    return std::pair{ std::move(user), std::move(password) };
}

std::expected
<
   std::string,
   grpc::Status
> 
UEventAnalysisToolBackend::GRPC::authorizationHeaderToToken(
    const grpc::string_ref &grpcHeader)
{
    const std::string_view header
    {   
        grpcHeader.data(),
        grpcHeader.size()
    };  
    const auto value = ::trim(header);
    if (value.empty())
    {   
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "Bearer credentials are absent"
            });
    }  

    const auto separator = value.find_first_of(" \t");
    if (separator == std::string_view::npos)
    {   
        return std::unexpected(
            grpc::Status
            {   
                grpc::StatusCode::UNAUTHENTICATED,
                "Bearer credentials malformed"
            }); 
    }   

    const auto scheme = value.substr(0, separator);
    if (!::equalsIgnoringCase(scheme, "Bearer"))
    {
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "Only Bearer credentials supported"
            });
    }

    const auto rest = ::trim(value.substr(separator + 1));
    if (rest.empty())
    {   
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "Empty JSON web token"
            });
    }

    if (std::ranges::any_of(rest,
                            [](const char c)
                            {
                                return std::isspace(
                                    static_cast<unsigned char> (c)) != 0;
                            }))
    {
        return std::unexpected(
            grpc::Status
            {
                grpc::StatusCode::UNAUTHENTICATED,
                "JSON web token cannot contain whitespace"
            });
    }
    return std::string{rest};
}
