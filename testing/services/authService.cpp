#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <grpcpp/client_context.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/support/channel_arguments.h>
#include <grpcpp/support/status.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include <sodium/utils.h>
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolBackend/services/authService.hpp"
#include <uEventAnalysisToolAPI/auth/v1/add_key_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/add_key_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/change_password_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/change_password_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/list_keys_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/list_keys_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_key_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_key_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/revoke_key_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/revoke_key_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/service.grpc.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/signature_algorithm.pb.h>
#include "../auth/integrationDatabase.hpp"
#include "../auth/keyAssertion.hpp"
#include "../auth/userSeeder.hpp"

using namespace UEventAnalysisToolBackend::Auth;
namespace V1 = UEventAnalysisToolAPI::Auth::V1;

// Integration test: the auth gRPC service's self-service routes, end to
// end.  As in adminService.cpp, the service runs in-process behind a real
// grpc::Server and is called through a generated stub, so what is checked
// is what a client sees: status codes, response fields, and how each
// route takes its credentials - Basic for AddKey and ChangePassword, a
// user bearer token for ListKeys and RevokeKey.  UserLoginAuthority's own
// tests cover the rules; this one covers the mapping of each refusal to
// a status code and the fields that make it across.

namespace
{

using Stub = V1::AuthService::Stub;
using Code = grpc::StatusCode;

const std::string issuer{"ueat-auth-service-test"};
const std::string keysAudience{issuer + "/keys"};
// What the seeder hashes.
const std::string password{"green eggs and ham"};
// What a provisional user changes to; meets policy() below.
const std::string newPassword{"green eggs and ham 2"};
constexpr int maximumKeys{3};
const std::chrono::seconds maximumLifetime{std::chrono::days {2}};

[[nodiscard]] std::string loadKey(const std::string &fileName)
{
    const auto path
        = std::filesystem::path{TESTING_DATA_DIR}/"keys"/fileName;
    std::ifstream file{path};
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open " + path.string());
    }
    std::stringstream contents;
    contents << file.rdbuf();
    return contents.str();
}

[[nodiscard]] Password::PasswordPolicy policy()
{
    Password::PasswordPolicy result;
    result.setMinimumAndMaximumLength(std::pair {12, 64});
    result.enableRequiresNumber();
    result.disableRequiresSpecialCharacter();
    result.enableNewAndOldPasswordMustDiffer();
    return result;
}

[[nodiscard]] UserLoginAuthorityOptions loginOptions(
    const UEventAnalysisToolBackend::Database::Credentials &credentials)
{
    UserLoginAuthorityOptions result;
    result.setDatabaseCredentials(credentials);
    result.setKeyPairAndAlgorithm(
        std::pair {loadKey("ed25519-public-key.pem"),
                   loadKey("ed25519-private-key.pem")},
        UserLoginAuthorityOptions::Algorithm::EdDSA25519);
    result.setIssuer(issuer);
    result.setTimeToLive(std::chrono::minutes {15});
    result.setPasswordHasherOptions(IntegrationDatabase::cheapHasherOptions());
    result.setPasswordPolicy(policy());
    result.setMaximumNumberOfLoginKeys(maximumKeys);
    result.setMaximumLoginKeyTimeToLive(maximumLifetime);
    return result;
}

[[nodiscard]] TokenVerifierOptions verifierOptions()
{
    TokenVerifierOptions result;
    result.setPublicKeyAndAlgorithm(
        loadKey("ed25519-public-key.pem"),
        TokenVerifierOptions::Algorithm::EdDSA25519);
    result.setIssuer(issuer);
    return result;
}

/// @result A token signed with the service's own key, so only its claims
///         decide whether it is accepted.
//NOLINTBEGIN(bugprone-easily-swappable-parameters)
[[nodiscard]] std::string signedToken(const std::string &subject,
                                      const std::string &scope)
//NOLINTEND(bugprone-easily-swappable-parameters)
{
    auto token = jwt::create<jwt::traits::boost_json> ();
    token.set_subject(subject)
         .set_issuer(issuer)
         .set_type("JWT")
         .set_issued_now()
         .set_expires_in(std::chrono::seconds {300});
    token.set_payload_claim("administrator", scope == "administrator");
    token.set_payload_claim("scope",
                            jwt::basic_claim<jwt::traits::boost_json> (scope));
    return token.sign(jwt::algorithm::ed25519(
                          loadKey("ed25519-public-key.pem"),
                          loadKey("ed25519-private-key.pem"),
                          "", ""));
}

[[nodiscard]] std::string basic(const std::string &name,
                                const std::string &withPassword)
{
    const auto credentials = name + ":" + withPassword;
    return "Basic "
         + IntegrationDatabase::toBase64(
               // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
               reinterpret_cast<const unsigned char *> (credentials.data()),
               credentials.size(), sodium_base64_VARIANT_ORIGINAL);
}

[[nodiscard]] std::string bearer(const std::string &token)
{
    return "Bearer " + token;
}

/// @brief One unary call through the stub with the authorization header -
///        if any - as a client sends it.
template<typename Response, typename Request, typename Method>
[[nodiscard]] std::pair<grpc::Status, Response>
    call(Stub &stub, Method method, const Request &request,
         const std::string &authorization)
{
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now()
                       + std::chrono::seconds {30});
    if (!authorization.empty())
    {
        context.AddMetadata("authorization", authorization);
    }
    Response response;
    auto status = (stub.*method)(&context, request, &response);
    return {std::move(status), std::move(response)};
}

[[nodiscard]] std::string bytesOf(const IntegrationDatabase::KeyPair &key)
{
    const auto publicKey = key.publicKey();
    return {publicKey.begin(), publicKey.end()};
}

/// @result A well-formed request to add key under keyName for subject.
//NOLINTBEGIN(bugprone-easily-swappable-parameters)
[[nodiscard]] V1::AddKeyRequest addKeyRequest(
    const IntegrationDatabase::KeyPair &key,
    const std::string &keyName,
    const std::string &subject)
//NOLINTEND(bugprone-easily-swappable-parameters)
{
    V1::AddKeyRequest request;
    request.set_name(keyName);
    request.set_public_key(bytesOf(key));
    request.set_assertion(
        key.sign(IntegrationDatabase::assertionHeader(),
                 IntegrationDatabase::assertionPayload(subject,
                                                       keysAudience)));
    request.set_algorithm(V1::SIGNATURE_ALGORITHM_ED25519);
    return request;
}

[[nodiscard]] V1::LoginWithKeyRequest loginWithKeyRequest(
    const IntegrationDatabase::KeyPair &key, const std::string &subject)
{
    V1::LoginWithKeyRequest request;
    request.set_public_key(bytesOf(key));
    request.set_assertion(
        key.sign(IntegrationDatabase::assertionHeader(),
                 IntegrationDatabase::assertionPayload(subject, issuer)));
    return request;
}

[[nodiscard]] V1::RevokeKeyRequest revokeKeyRequest(const std::string &keyName)
{
    V1::RevokeKeyRequest request;
    request.set_name(keyName);
    return request;
}

}

TEST_CASE("UEventAnalysisToolBackend::Services::AuthService",
          "[.integration][AuthService]")
{
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-auth-service-test-" + suffix;
    const auto backendCredentials
        = IntegrationDatabase::credentials(application);
    const auto superuserCredentials
        = IntegrationDatabase::superuserCredentials(application + "-seeder");
    if (!backendCredentials || !superuserCredentials)
    {
        SKIP("Set UEAT_TEST_DB_{HOST,PORT,NAME,USER,PASSWORD} and "
             "UEAT_TEST_DB_SUPERUSER{,_PASSWORD} to run this");
    }

    // N.B. auth.* lower-cases names, so these are written lower case.
    const std::string user{"guy-am-i-" + suffix};
    const std::string other{"sam-i-am-" + suffix};
    const std::string newcomer{"i-am-sam-" + suffix};
    INFO("suffix = " << suffix);

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(user, false);
    seeder.addUser(other, false);
    seeder.addProvisionalUser(newcomer);

    auto logger = IntegrationDatabase::quietLogger("authServiceTests");
    auto authority = std::make_shared<UserLoginAuthority>
        (loginOptions(*backendCredentials), logger);
    auto verifier = std::make_shared<UserTokenVerifier>
        (verifierOptions(), logger);
    REQUIRE(authority->isInitialized());
    REQUIRE(verifier->isInitialized());

    // Declared before the server, so the server - destroyed first -
    // stops calling into it before it goes.
    UEventAnalysisToolBackend::Services::AuthService service{
        authority, verifier, logger};
    grpc::ServerBuilder builder;
    builder.RegisterService(&service);
    const auto server = builder.BuildAndStart();
    REQUIRE(server != nullptr);
    const auto stub
        = V1::AuthService::NewStub(
              server->InProcessChannel(grpc::ChannelArguments {}));

    const auto loginWithPassword = [&](const std::string &name,
                                       const std::string &withPassword)
    {
        return call<V1::LoginWithPasswordResponse>(
            *stub, &Stub::LoginWithPassword, V1::LoginWithPasswordRequest {},
            basic(name, withPassword));
    };
    const auto addKey = [&](const V1::AddKeyRequest &request,
                            const std::string &name,
                            const std::string &withPassword = password)
    {
        return call<V1::AddKeyResponse>(*stub, &Stub::AddKey, request,
                                        basic(name, withPassword));
    };
    const auto loginWithKey = [&](const IntegrationDatabase::KeyPair &key,
                                  const std::string &name)
    {
        return call<V1::LoginWithKeyResponse>(
            *stub, &Stub::LoginWithKey, loginWithKeyRequest(key, name), "");
    };
    const auto listKeys = [&](const std::string &token)
    {
        return call<V1::ListKeysResponse>(
            *stub, &Stub::ListKeys, V1::ListKeysRequest {}, bearer(token));
    };
    const auto revokeKey = [&](const std::string &keyName,
                               const std::string &token)
    {
        return call<V1::RevokeKeyResponse>(
            *stub, &Stub::RevokeKey, revokeKeyRequest(keyName),
            bearer(token));
    };
    const auto tokenFor = [&](const std::string &name)
    {
        const auto [status, response] = loginWithPassword(name, password);
        INFO(status.error_message());
        REQUIRE(status.ok());
        return response.json_web_token();
    };

    SECTION("From an issued password to logging in with a key and back")
    {
        const IntegrationDatabase::KeyPair laptop;

        // An issued password logs no one in and adds no keys.
        REQUIRE(loginWithPassword(newcomer, password).first.error_code()
             == Code::FAILED_PRECONDITION);
        REQUIRE(addKey(addKeyRequest(laptop, "laptop", newcomer), newcomer)
                .first.error_code() == Code::FAILED_PRECONDITION);
        REQUIRE_FALSE(seeder.hasKey(newcomer, "laptop"));

        V1::ChangePasswordRequest change;
        change.set_new_password(newPassword);
        const auto changed
            = call<V1::ChangePasswordResponse>(
                  *stub, &Stub::ChangePassword, change,
                  basic(newcomer, password));
        INFO(changed.first.error_message());
        REQUIRE(changed.first.ok());

        const auto added = addKey(addKeyRequest(laptop, "laptop", newcomer),
                                  newcomer, newPassword);
        INFO(added.first.error_message());
        REQUIRE(added.first.ok());

        const auto [loginStatus, login] = loginWithKey(laptop, newcomer);
        REQUIRE(loginStatus.ok());
        const auto token = login.json_web_token();
        REQUIRE_FALSE(token.empty());

        // The key, as the client sees it.
        {
            const auto [status, keys] = listKeys(token);
            INFO(status.error_message());
            REQUIRE(status.ok());
            REQUIRE(keys.active_keys_size() == 1);
            REQUIRE(keys.inactive_keys_size() == 0);
            const auto &key = keys.active_keys(0);
            REQUIRE(key.name() == "laptop");
            REQUIRE(key.fingerprint()
                 == seeder.keyFingerprint(newcomer, "laptop"));
            REQUIRE(key.algorithm() == V1::SIGNATURE_ALGORITHM_ED25519);
            REQUIRE(key.has_registered());
            REQUIRE(key.has_last_used());
            // Unset expires_after means the longest allowed.
            REQUIRE(key.has_expires());
            const auto lifetime
                = key.expires().seconds() - key.registered().seconds();
            REQUIRE(lifetime >= maximumLifetime.count() - 5);
            REQUIRE(lifetime <= maximumLifetime.count() + 5);
        }

        REQUIRE(revokeKey("laptop", token).first.ok());
        {
            const auto [status, keys] = listKeys(token);
            REQUIRE(status.ok());
            REQUIRE(keys.active_keys_size() == 0);
            REQUIRE(keys.inactive_keys_size() == 1);
            const auto &key = keys.inactive_keys(0);
            REQUIRE(key.name() == "laptop");
            REQUIRE(key.reason()
                 == V1::ListKeysResponse::InactiveKey::REASON_REVOKED);
            REQUIRE(key.has_invalidated());
        }
        REQUIRE(loginWithKey(laptop, newcomer).first.error_code()
             == Code::UNAUTHENTICATED);
        REQUIRE(revokeKey("laptop", token).first.error_code()
             == Code::NOT_FOUND);
    }
    SECTION("AddKey maps each refusal to a status code")
    {
        const IntegrationDatabase::KeyPair desktop;
        const auto good = [&]
        {
            return addKeyRequest(desktop, "desktop", user);
        };
        const auto codeOf = [&](const V1::AddKeyRequest &request)
        {
            const auto [status, response] = addKey(request, user);
            return status.error_code();
        };

        // Credentials.
        REQUIRE(call<V1::AddKeyResponse>(*stub, &Stub::AddKey, good(), "")
                .first.error_code() == Code::UNAUTHENTICATED);
        REQUIRE(addKey(good(), user, "wrong password")
                .first.error_code() == Code::UNAUTHENTICATED);
        REQUIRE(addKey(good(), "nobody-" + suffix)
                .first.error_code() == Code::UNAUTHENTICATED);
        // A bearer token is not Basic credentials.
        REQUIRE(call<V1::AddKeyResponse>(*stub, &Stub::AddKey, good(),
                                         bearer(tokenFor(user)))
                .first.error_code() == Code::UNAUTHENTICATED);

        // Missing fields.
        {
            auto request = good();
            request.clear_name();
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }
        {
            auto request = good();
            request.clear_public_key();
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }
        {
            auto request = good();
            request.clear_assertion();
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }
        {
            auto request = good();
            request.clear_algorithm();
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }

        // Bad values.
        {
            auto request = good();
            request.set_algorithm(V1::SIGNATURE_ALGORITHM_NOT_SPECIFIED);
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
            request.set_algorithm(static_cast<V1::SignatureAlgorithm> (7));
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }
        {
            auto request = good();
            request.set_name("no spaces allowed");
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }
        {
            auto request = good();
            request.set_public_key(bytesOf(desktop).substr(0, 16));
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }
        {
            // Signed for logging in, not for adding a key.
            auto request = good();
            request.set_assertion(
                loginWithKeyRequest(desktop, user).assertion());
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }
        {
            auto request = good();
            request.mutable_expires_after()->set_seconds(0);
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
            request.mutable_expires_after()->set_seconds(
                maximumLifetime.count() + 1);
            REQUIRE(codeOf(request) == Code::INVALID_ARGUMENT);
        }
        // None of that added anything.
        REQUIRE_FALSE(seeder.hasKey(user, "desktop"));

        // A requested lifetime is kept; the fraction is dropped.
        {
            auto request = good();
            request.mutable_expires_after()->set_seconds(3600);
            request.mutable_expires_after()->set_nanos(900'000'000);
            REQUIRE(codeOf(request) == Code::OK);
            const auto expiresIn = seeder.keyExpiresIn(user, "desktop");
            REQUIRE(expiresIn.has_value());
            REQUIRE(expiresIn.value_or(std::chrono::seconds {0}).count()
                 <= 3600);
            REQUIRE(expiresIn.value_or(std::chrono::seconds {0}).count()
                 >= 3600 - 5);
        }

        // Clashes.
        const IntegrationDatabase::KeyPair another;
        REQUIRE(codeOf(addKeyRequest(another, "desktop", user))
             == Code::ALREADY_EXISTS);
        REQUIRE(codeOf(addKeyRequest(desktop, "another", user))
             == Code::ALREADY_EXISTS);

        // The cap: desktop plus two more, then no more.
        const IntegrationDatabase::KeyPair second;
        const IntegrationDatabase::KeyPair third;
        const IntegrationDatabase::KeyPair fourth;
        REQUIRE(codeOf(addKeyRequest(second, "second", user)) == Code::OK);
        REQUIRE(codeOf(addKeyRequest(third, "third", user)) == Code::OK);
        REQUIRE(codeOf(addKeyRequest(fourth, "fourth", user))
             == Code::RESOURCE_EXHAUSTED);
        REQUIRE_FALSE(seeder.hasKey(user, "fourth"));
    }
    SECTION("ListKeys and RevokeKey take only a user's bearer token")
    {
        const IntegrationDatabase::KeyPair laptop;
        seeder.addKey(user, "laptop", laptop.encodedPublicKey());

        const auto listCode = [&](const std::string &authorization)
        {
            return call<V1::ListKeysResponse>(
                *stub, &Stub::ListKeys, V1::ListKeysRequest {},
                authorization).first.error_code();
        };
        const auto revokeCode = [&](const std::string &authorization)
        {
            return call<V1::RevokeKeyResponse>(
                *stub, &Stub::RevokeKey, revokeKeyRequest("laptop"),
                authorization).first.error_code();
        };
        const std::vector<std::pair<std::string, std::string>> refused
        {
            {"no header", ""},
            {"Basic credentials", basic(user, password)},
            {"garbage", bearer("not.a.token")},
            // Right key and issuer, wrong scope.
            {"administrator scope", bearer(signedToken(user, "administrator"))},
            // A user deleted since the token was minted.
            {"unknown user", bearer(signedToken("nobody-" + suffix, "user"))},
        };
        for (const auto &[label, authorization] : refused)
        {
            INFO(label);
            REQUIRE(listCode(authorization) == Code::UNAUTHENTICATED);
            REQUIRE(revokeCode(authorization) == Code::UNAUTHENTICATED);
        }
        // Still there after all that.
        REQUIRE_FALSE(seeder.keyIsRevoked(user, "laptop"));

        // The same claims with the user scope are fine.
        REQUIRE(listCode(bearer(signedToken(user, "user"))) == Code::OK);
    }
    SECTION("A user revokes only their own keys")
    {
        const IntegrationDatabase::KeyPair theirs;
        seeder.addKey(other, "theirs", theirs.encodedPublicKey());
        const auto token = tokenFor(user);

        REQUIRE(revokeKey("theirs", token).first.error_code()
             == Code::NOT_FOUND);
        REQUIRE_FALSE(seeder.keyIsRevoked(other, "theirs"));

        const V1::RevokeKeyRequest unnamed;
        REQUIRE(call<V1::RevokeKeyResponse>(*stub, &Stub::RevokeKey, unnamed,
                                            bearer(token))
                .first.error_code() == Code::INVALID_ARGUMENT);

        // And sees only their own.
        const auto [status, keys] = listKeys(token);
        REQUIRE(status.ok());
        REQUIRE(keys.active_keys_size() == 0);
        REQUIRE(keys.inactive_keys_size() == 0);
    }
}
