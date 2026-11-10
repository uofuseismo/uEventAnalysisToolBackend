#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
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
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/administratorTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/tokenVerifierOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userAdministration.hpp"
#include "uEventAnalysisToolBackend/auth/userAdministrationOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolBackend/services/adminService.hpp"
#include <uEventAnalysisToolAPI/admin/v1/create_user_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/create_user_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/delete_user_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/delete_user_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/list_users_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/list_users_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/login_with_password_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/login_with_password_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/permission.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/reset_password_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/reset_password_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/revoke_administrator_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/revoke_administrator_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/revoke_permission_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/revoke_permission_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/service.grpc.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/set_administrator_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/set_administrator_response.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/set_permission_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/set_permission_response.pb.h>
#include "../auth/integrationDatabase.hpp"
#include "../auth/keyAssertion.hpp"
#include "../auth/userSeeder.hpp"

using namespace UEventAnalysisToolBackend::Auth;
namespace V1 = UEventAnalysisToolAPI::Admin::V1;

// Integration test: the admin gRPC service, end to end.  The service
// runs in-process behind a real grpc::Server and is called through a
// generated stub, so what is checked is what a client sees: status
// codes, response fields, and bearer handling.  The classes underneath
// have their own tests; this one is about the wiring between them -
// a handler that drops a field or maps an error to the wrong code
// passes those and fails here.
//
// The database setup is the same as the auth integration tests: the
// service connects as the backend role (UEAT_TEST_DB_USER), users are
// seeded and removed through UEAT_TEST_DB_SUPERUSER, and every name
// carries a random suffix.

namespace
{

using Result = IAuthenticator::Result;
using Stub = V1::AdminService::Stub;
using Permissions = std::vector<std::pair<std::string, std::string>>;

const std::string userIssuer{"ueat-admin-service-test-user"};
const std::string adminIssuer{"ueat-admin-service-test-admin"};
// What the seeder hashes.
const std::string password{"green eggs and ham"};

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

[[nodiscard]] UserLoginAuthorityOptions userLoginOptions(
    const UEventAnalysisToolBackend::Database::Credentials &credentials)
{
    UserLoginAuthorityOptions result;
    result.setDatabaseCredentials(credentials);
    result.setKeyPairAndAlgorithm(
        std::pair {loadKey("ed25519-public-key.pem"),
                   loadKey("ed25519-private-key.pem")},
        UserLoginAuthorityOptions::Algorithm::EdDSA25519);
    result.setIssuer(userIssuer);
    result.setTimeToLive(std::chrono::minutes {15});
    result.setPasswordHasherOptions(IntegrationDatabase::cheapHasherOptions());
    result.setPasswordPolicy(policy());
    return result;
}

[[nodiscard]] AdministratorLoginAuthorityOptions adminLoginOptions(
    const UEventAnalysisToolBackend::Database::Credentials &credentials)
{
    AdministratorLoginAuthorityOptions result;
    result.setDatabaseCredentials(credentials);
    result.setKeyPairAndAlgorithm(
        std::pair {loadKey("ed25519-admin-public-key.pem"),
                   loadKey("ed25519-admin-private-key.pem")},
        AdministratorLoginAuthorityOptions::Algorithm::EdDSA25519);
    result.setIssuer(adminIssuer);
    result.setTimeToLive(std::chrono::minutes {10});
    return result;
}

//NOLINTBEGIN(bugprone-easily-swappable-parameters)
[[nodiscard]] TokenVerifierOptions verifierOptions(const std::string &keyFile,
                                                   const std::string &issuer)
//NOLINTEND(bugprone-easily-swappable-parameters)
{
    TokenVerifierOptions result;
    result.setPublicKeyAndAlgorithm(
        loadKey(keyFile), TokenVerifierOptions::Algorithm::EdDSA25519);
    result.setIssuer(issuer);
    return result;
}

[[nodiscard]] UserAdministrationOptions administrationOptions(
    const UEventAnalysisToolBackend::Database::Credentials &credentials)
{
    UserAdministrationOptions result;
    result.setDatabaseCredentials(credentials);
    result.setPasswordHasherOptions(IntegrationDatabase::cheapHasherOptions());
    result.setPasswordPolicy(policy());
    result.setIssuedPasswordTimeToLive(std::chrono::hours {1});
    return result;
}

/// @brief One unary call through the stub, with the bearer token - if
///        any - in the authorization header, as a client sends it.
template<typename Response, typename Request, typename Method>
[[nodiscard]] std::pair<grpc::Status, Response>
    call(Stub &stub, Method method, const Request &request,
         const std::string &token)
{
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now()
                       + std::chrono::seconds {30});
    if (!token.empty())
    {
        context.AddMetadata("authorization", "Bearer " + token);
    }
    Response response;
    auto status = (stub.*method)(&context, request, &response);
    return {std::move(status), std::move(response)};
}

template<typename Request>
[[nodiscard]] Request named(const std::string &name)
{
    Request request;
    request.set_name(name);
    return request;
}

}

TEST_CASE("UEventAnalysisToolBackend::Services::AdminService",
          "[.integration][AdminService]")
{
    const auto suffix = IntegrationDatabase::uniqueSuffix();
    const auto application = "ueat-admin-service-test-" + suffix;
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
    const std::string administrator{"sam-i-am-" + suffix};
    const std::string user{"guy-am-i-" + suffix};
    const std::string provisionalAdministrator{"sam-i-am-provisional-" + suffix};
    const std::string newcomer{"guy-am-i-new-" + suffix};
    const std::string stranger{"stranger-" + suffix};
    INFO("suffix = " << suffix);

    IntegrationDatabase::UserSeeder seeder{*superuserCredentials, password};
    seeder.addUser(administrator, true);
    seeder.addUser(user, false);
    seeder.addProvisionalUser(provisionalAdministrator, true);
    seeder.track(newcomer);

    auto logger = IntegrationDatabase::quietLogger("adminServiceTests");
    auto userAuthority = std::make_shared<UserLoginAuthority>
        (userLoginOptions(*backendCredentials), logger);
    auto adminAuthority = std::make_shared<AdministratorLoginAuthority>
        (adminLoginOptions(*backendCredentials), logger);
    auto adminVerifier = std::make_shared<AdministratorTokenVerifier>
        (verifierOptions("ed25519-admin-public-key.pem", adminIssuer), logger);
    auto userVerifier = std::make_shared<UserTokenVerifier>
        (verifierOptions("ed25519-public-key.pem", userIssuer), logger);
    auto administration = std::make_shared<UserAdministration>
        (administrationOptions(*backendCredentials), logger);
    REQUIRE(userAuthority->isInitialized());
    REQUIRE(adminAuthority->isInitialized());
    REQUIRE(administration->isInitialized());

    // Declared before the server, so the server - destroyed first -
    // stops calling into it before it goes.
    UEventAnalysisToolBackend::Services::AdminService service{
        adminAuthority, adminVerifier, administration, userVerifier, logger};
    grpc::ServerBuilder builder;
    builder.RegisterService(&service);
    const auto server = builder.BuildAndStart();
    REQUIRE(server != nullptr);
    const auto stub
        = V1::AdminService::NewStub(
              server->InProcessChannel(grpc::ChannelArguments {}));

    // What a client holds after logging in.
    const auto userTokenFor = [&](const std::string &name,
                                  const std::string &withPassword)
    {
        const auto token = userAuthority->loginWithPassword(
                               std::pair {name, withPassword});
        REQUIRE(token.has_value());
        return token.value_or(std::string {});
    };
    // ...and after stepping up to administrator over the wire.
    const auto adminTokenFor = [&](const std::string &name)
    {
        V1::LoginWithPasswordRequest request;
        request.set_password(password);
        const auto [status, response]
            = call<V1::LoginWithPasswordResponse>(
                  *stub, &Stub::LoginWithPassword, request,
                  userTokenFor(name, password));
        INFO(status.error_message());
        REQUIRE(status.ok());
        REQUIRE_FALSE(response.json_web_token().empty());
        return response.json_web_token();
    };
    // What a user logging in now would be allowed to do.
    const auto permissionsOf = [&](const std::string &name) -> Permissions
    {
        const auto [result, claims]
            = userVerifier->verify(userTokenFor(name, password));
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        Permissions permissions;
        if (claims){permissions.assign(claims->begin(), claims->end());}
        std::ranges::sort(permissions);
        return permissions;
    };

    // Every admin route, called for an existing user, with a given token.
    // Each returns the status code.
    using Route = std::function<grpc::StatusCode (const std::string &)>;
    const std::vector<std::pair<std::string, Route>> adminRoutes
    {
        {"CreateUser", [&](const std::string &token)
         {
             return call<V1::CreateUserResponse>(
                 *stub, &Stub::CreateUser,
                 named<V1::CreateUserRequest>(newcomer),
                 token).first.error_code();
         }},
        {"ResetPassword", [&](const std::string &token)
         {
             auto request = named<V1::ResetPasswordRequest>(user);
             request.set_revoke_keys(false);
             return call<V1::ResetPasswordResponse>(
                 *stub, &Stub::ResetPassword, request, token)
                 .first.error_code();
         }},
        {"DeleteUser", [&](const std::string &token)
         {
             return call<V1::DeleteUserResponse>(
                 *stub, &Stub::DeleteUser,
                 named<V1::DeleteUserRequest>(user),
                 token).first.error_code();
         }},
        {"SetPermission", [&](const std::string &token)
         {
             auto request = named<V1::SetPermissionRequest>(user);
             request.set_schema("utah");
             request.set_permission(V1::PERMISSION_READ_WRITE);
             return call<V1::SetPermissionResponse>(
                 *stub, &Stub::SetPermission, request, token)
                 .first.error_code();
         }},
        {"RevokePermission", [&](const std::string &token)
         {
             auto request = named<V1::RevokePermissionRequest>(user);
             request.set_schema("utah");
             return call<V1::RevokePermissionResponse>(
                 *stub, &Stub::RevokePermission, request, token)
                 .first.error_code();
         }},
        {"SetAdministrator", [&](const std::string &token)
         {
             return call<V1::SetAdministratorResponse>(
                 *stub, &Stub::SetAdministrator,
                 named<V1::SetAdministratorRequest>(user),
                 token).first.error_code();
         }},
        {"RevokeAdministrator", [&](const std::string &token)
         {
             return call<V1::RevokeAdministratorResponse>(
                 *stub, &Stub::RevokeAdministrator,
                 named<V1::RevokeAdministratorRequest>(administrator),
                 token).first.error_code();
         }},
        {"ListUsers", [&](const std::string &token)
         {
             return call<V1::ListUsersResponse>(
                 *stub, &Stub::ListUsers, V1::ListUsersRequest {},
                 token).first.error_code();
         }},
    };

    SECTION("An administrator steps up from a user token")
    {
        const auto adminToken = adminTokenFor(administrator);
        const auto [result, claims] = adminVerifier->verify(adminToken);
        REQUIRE(result == Result::Authenticated);
        REQUIRE(claims.has_value());
        if (claims)
        {
            REQUIRE(claims->getUser() == administrator);
            REQUIRE(Claims::isAdministrator(*claims));
        }
    }
    SECTION("The step-up needs a user token, the password, and an admin")
    {
        V1::LoginWithPasswordRequest request;
        request.set_password(password);
        // No token at all.
        REQUIRE(call<V1::LoginWithPasswordResponse>(
                    *stub, &Stub::LoginWithPassword, request, "")
                .first.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        // An admin token is not a user token.
        REQUIRE(call<V1::LoginWithPasswordResponse>(
                    *stub, &Stub::LoginWithPassword, request,
                    adminTokenFor(administrator))
                .first.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        // A user who is not an administrator.
        const auto [status, response]
            = call<V1::LoginWithPasswordResponse>(
                  *stub, &Stub::LoginWithPassword, request,
                  userTokenFor(user, password));
        REQUIRE(status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        REQUIRE(response.json_web_token().empty());
        // The wrong password.
        V1::LoginWithPasswordRequest wrong;
        wrong.set_password("not " + password);
        REQUIRE(call<V1::LoginWithPasswordResponse>(
                    *stub, &Stub::LoginWithPassword, wrong,
                    userTokenFor(administrator, password))
                .first.error_code() == grpc::StatusCode::UNAUTHENTICATED);
    }
    SECTION("Every admin route needs an admin token")
    {
        const auto userToken = userTokenFor(administrator, password);
        for (const auto &[name, route] : adminRoutes)
        {
            INFO("route = " << name);
            REQUIRE(route("") == grpc::StatusCode::UNAUTHENTICATED);
            REQUIRE(route("not-a-token") == grpc::StatusCode::UNAUTHENTICATED);
            // The administrator's own user token is still not enough.
            REQUIRE(route(userToken) == grpc::StatusCode::UNAUTHENTICATED);
        }
        // Nothing happened.
        REQUIRE_FALSE(seeder.exists(newcomer));
        REQUIRE(seeder.exists(user));
        REQUIRE_FALSE(seeder.isProvisional(user));
        REQUIRE_FALSE(seeder.isAdministrator(user));
        REQUIRE(seeder.isAdministrator(administrator));
        REQUIRE(permissionsOf(user).empty());
    }
    SECTION("An admin token outlives the authority behind it, but not past "
            "the database")
    {
        // The deputy steps up, then is demoted.  Their token still
        // verifies, but every call is checked against the users table.
        const auto deputy = "sam-i-am-deputy-" + suffix;
        seeder.addUser(deputy, true);
        const auto deputyToken = adminTokenFor(deputy);
        REQUIRE(call<V1::RevokeAdministratorResponse>(
                    *stub, &Stub::RevokeAdministrator,
                    named<V1::RevokeAdministratorRequest>(deputy),
                    adminTokenFor(administrator)).first.ok());
        for (const auto &[name, route] : adminRoutes)
        {
            INFO("route = " << name);
            REQUIRE(route(deputyToken) == grpc::StatusCode::PERMISSION_DENIED);
        }
        REQUIRE_FALSE(seeder.exists(newcomer));
        REQUIRE(seeder.isAdministrator(administrator));
    }
    SECTION("CreateUser returns a temporary password that works")
    {
        const auto adminToken = adminTokenFor(administrator);
        const auto [status, response]
            = call<V1::CreateUserResponse>(
                  *stub, &Stub::CreateUser,
                  named<V1::CreateUserRequest>(" " + newcomer + " "),
                  adminToken);
        INFO(status.error_message());
        REQUIRE(status.ok());
        // The stored spelling, which is what the user logs in as.
        REQUIRE(response.user() == newcomer);
        REQUIRE_FALSE(response.temporary_password().empty());
        const auto login = userAuthority->loginWithPassword(
            std::pair {newcomer, response.temporary_password()});
        REQUIRE_FALSE(login.has_value());
        REQUIRE(login.error() == Result::PasswordChangeRequired);

        REQUIRE(call<V1::CreateUserResponse>(
                    *stub, &Stub::CreateUser,
                    named<V1::CreateUserRequest>(newcomer), adminToken)
                .first.error_code() == grpc::StatusCode::ALREADY_EXISTS);
        for (const auto &bad : {std::string {}, std::string {"b o b"}})
        {
            INFO("name = '" << bad << "'");
            REQUIRE(call<V1::CreateUserResponse>(
                        *stub, &Stub::CreateUser,
                        named<V1::CreateUserRequest>(bad), adminToken)
                    .first.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        }
    }
    SECTION("ResetPassword returns a temporary password that works")
    {
        const IntegrationDatabase::KeyPair key;
        seeder.addKey(user, "laptop", key.encodedPublicKey());
        const auto adminToken = adminTokenFor(administrator);
        auto request = named<V1::ResetPasswordRequest>(user);
        request.set_revoke_keys(false);
        const auto [status, response]
            = call<V1::ResetPasswordResponse>(
                  *stub, &Stub::ResetPassword, request, adminToken);
        INFO(status.error_message());
        REQUIRE(status.ok());
        REQUIRE_FALSE(response.temporary_password().empty());
        const auto issued = userAuthority->loginWithPassword(
            std::pair {user, response.temporary_password()});
        REQUIRE_FALSE(issued.has_value());
        REQUIRE(issued.error() == Result::PasswordChangeRequired);
        const auto old
            = userAuthority->loginWithPassword(std::pair {user, password});
        REQUIRE_FALSE(old.has_value());
        REQUIRE(old.error() == Result::InvalidCredentials);
        // A forgot-password reset leaves the keys alone...
        REQUIRE_FALSE(seeder.keyIsRevoked(user, "laptop"));

        // ...a compromise reset does not.
        request.set_revoke_keys(true);
        const auto [compromised, compromisedResponse]
            = call<V1::ResetPasswordResponse>(
                  *stub, &Stub::ResetPassword, request, adminToken);
        REQUIRE(compromised.ok());
        REQUIRE_FALSE(compromisedResponse.temporary_password().empty());
        REQUIRE(compromisedResponse.temporary_password()
                != response.temporary_password());
        REQUIRE(seeder.keyIsRevoked(user, "laptop"));
    }
    SECTION("ResetPassword must be told whether to revoke keys")
    {
        // The two reasons for a reset want opposite things, so an unset
        // revoke_keys is refused rather than defaulted.
        const auto [status, response]
            = call<V1::ResetPasswordResponse>(
                  *stub, &Stub::ResetPassword,
                  named<V1::ResetPasswordRequest>(user),
                  adminTokenFor(administrator));
        REQUIRE(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        REQUIRE(response.temporary_password().empty());
        REQUIRE_FALSE(seeder.isProvisional(user));
    }
    SECTION("A user who does not exist is NOT_FOUND")
    {
        const auto adminToken = adminTokenFor(administrator);
        auto reset = named<V1::ResetPasswordRequest>(stranger);
        reset.set_revoke_keys(false);
        REQUIRE(call<V1::ResetPasswordResponse>(
                    *stub, &Stub::ResetPassword, reset, adminToken)
                .first.error_code() == grpc::StatusCode::NOT_FOUND);
        REQUIRE(call<V1::DeleteUserResponse>(
                    *stub, &Stub::DeleteUser,
                    named<V1::DeleteUserRequest>(stranger), adminToken)
                .first.error_code() == grpc::StatusCode::NOT_FOUND);
        auto set = named<V1::SetPermissionRequest>(stranger);
        set.set_schema("utah");
        set.set_permission(V1::PERMISSION_READ_ONLY);
        REQUIRE(call<V1::SetPermissionResponse>(
                    *stub, &Stub::SetPermission, set, adminToken)
                .first.error_code() == grpc::StatusCode::NOT_FOUND);
        REQUIRE(call<V1::SetAdministratorResponse>(
                    *stub, &Stub::SetAdministrator,
                    named<V1::SetAdministratorRequest>(stranger), adminToken)
                .first.error_code() == grpc::StatusCode::NOT_FOUND);
        REQUIRE_FALSE(seeder.exists(stranger));
    }
    SECTION("Permissions set over the wire are what the next login carries")
    {
        const auto adminToken = adminTokenFor(administrator);
        auto set = named<V1::SetPermissionRequest>(user);
        set.set_schema("utah");
        set.set_permission(V1::PERMISSION_READ_WRITE);
        REQUIRE(call<V1::SetPermissionResponse>(
                    *stub, &Stub::SetPermission, set, adminToken).first.ok());
        REQUIRE(permissionsOf(user) == Permissions {{"utah", "read_write"}});

        auto revoke = named<V1::RevokePermissionRequest>(user);
        revoke.set_schema("utah");
        REQUIRE(call<V1::RevokePermissionResponse>(
                    *stub, &Stub::RevokePermission, revoke, adminToken)
                .first.ok());
        REQUIRE(permissionsOf(user).empty());
        // Nothing left to revoke.
        REQUIRE(call<V1::RevokePermissionResponse>(
                    *stub, &Stub::RevokePermission, revoke, adminToken)
                .first.error_code() == grpc::StatusCode::NOT_FOUND);
    }
    SECTION("A permission needs a level and a real schema")
    {
        const auto adminToken = adminTokenFor(administrator);
        auto unspecified = named<V1::SetPermissionRequest>(user);
        unspecified.set_schema("utah");
        REQUIRE(call<V1::SetPermissionResponse>(
                    *stub, &Stub::SetPermission, unspecified, adminToken)
                .first.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        for (const auto &schema :
             {std::string {}, std::string {"atlantis"}, std::string {"utah;drop"}})
        {
            INFO("schema = '" << schema << "'");
            auto set = named<V1::SetPermissionRequest>(user);
            set.set_schema(schema);
            set.set_permission(V1::PERMISSION_READ_ONLY);
            REQUIRE(call<V1::SetPermissionResponse>(
                        *stub, &Stub::SetPermission, set, adminToken)
                    .first.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        }
        REQUIRE(permissionsOf(user).empty());
    }
    SECTION("Administrator set and revoked over the wire")
    {
        const auto adminToken = adminTokenFor(administrator);
        REQUIRE(call<V1::SetAdministratorResponse>(
                    *stub, &Stub::SetAdministrator,
                    named<V1::SetAdministratorRequest>(user), adminToken)
                .first.ok());
        REQUIRE(seeder.isAdministrator(user));
        // And the new administrator can step up.
        REQUIRE_FALSE(adminTokenFor(user).empty());
        REQUIRE(call<V1::RevokeAdministratorResponse>(
                    *stub, &Stub::RevokeAdministrator,
                    named<V1::RevokeAdministratorRequest>(user), adminToken)
                .first.ok());
        REQUIRE_FALSE(seeder.isAdministrator(user));
    }
    SECTION("DeleteUser removes the user")
    {
        const auto adminToken = adminTokenFor(administrator);
        REQUIRE(call<V1::DeleteUserResponse>(
                    *stub, &Stub::DeleteUser,
                    named<V1::DeleteUserRequest>(user), adminToken)
                .first.ok());
        REQUIRE_FALSE(seeder.exists(user));
        REQUIRE(call<V1::DeleteUserResponse>(
                    *stub, &Stub::DeleteUser,
                    named<V1::DeleteUserRequest>(user), adminToken)
                .first.error_code() == grpc::StatusCode::NOT_FOUND);
    }
    SECTION("ListUsers arrives intact")
    {
        const IntegrationDatabase::KeyPair key;
        seeder.addKey(user, "laptop", key.encodedPublicKey());
        seeder.setPermission(user, "ynp", "read_only");
        const auto adminToken = adminTokenFor(administrator);
        const auto [status, response]
            = call<V1::ListUsersResponse>(
                  *stub, &Stub::ListUsers, V1::ListUsersRequest {},
                  adminToken);
        INFO(status.error_message());
        REQUIRE(status.ok());

        const auto findIn = [](const auto &users, const std::string &name)
        {
            return std::ranges::find_if(users, [&](const auto &u)
                                        {
                                            return u.name() == name;
                                        });
        };
        const auto &active = response.active_users();
        const auto &provisional = response.provisional_users();

        const auto admin = findIn(active, administrator);
        REQUIRE(admin != active.end());
        REQUIRE(admin->administrator());
        // Stepping up is a login.
        REQUIRE(admin->has_last_login());
        REQUIRE(admin->has_created());
        REQUIRE(admin->has_password_updated());

        const auto guy = findIn(active, user);
        REQUIRE(guy != active.end());
        REQUIRE_FALSE(guy->administrator());
        REQUIRE_FALSE(guy->has_last_login());
        REQUIRE(guy->permissions_size() == 1);
        REQUIRE(guy->permissions(0).schema() == "ynp");
        REQUIRE(guy->permissions(0).permission() == V1::PERMISSION_READ_ONLY);
        REQUIRE(guy->permissions(0).has_granted());
        REQUIRE(guy->active_keys_size() == 1);
        REQUIRE(guy->active_keys(0).name() == "laptop");
        REQUIRE(guy->active_keys(0).fingerprint()
                == seeder.keyFingerprint(user, "laptop"));
        REQUIRE(guy->active_keys(0).algorithm()
                == V1::ListUsersResponse::SIGNATURE_ALGORITHM_ED25519);
        REQUIRE_FALSE(guy->active_keys(0).has_expires());
        REQUIRE_FALSE(guy->active_keys(0).has_last_used());
        REQUIRE(guy->inactive_keys_size() == 0);

        const auto pending = findIn(provisional, provisionalAdministrator);
        REQUIRE(pending != provisional.end());
        REQUIRE(pending->administrator());
        REQUIRE(pending->has_expiration());
        REQUIRE_FALSE(pending->expired());
        REQUIRE_FALSE(pending->password_reset());

        for (const auto &name : {administrator, user})
        {
            REQUIRE(findIn(provisional, name) == provisional.end());
        }
        REQUIRE(findIn(active, provisionalAdministrator) == active.end());
        REQUIRE(findIn(active, stranger) == active.end());
    }
    SECTION("The last administrator is a failed precondition")
    {
        if (seeder.countActiveAdministrators() != 1)
        {
            SKIP("Another administrator exists, so "
                 << administrator << " is not the last one");
        }
        const auto adminToken = adminTokenFor(administrator);
        REQUIRE(call<V1::DeleteUserResponse>(
                    *stub, &Stub::DeleteUser,
                    named<V1::DeleteUserRequest>(administrator), adminToken)
                .first.error_code() == grpc::StatusCode::FAILED_PRECONDITION);
        REQUIRE(call<V1::RevokeAdministratorResponse>(
                    *stub, &Stub::RevokeAdministrator,
                    named<V1::RevokeAdministratorRequest>(administrator),
                    adminToken)
                .first.error_code() == grpc::StatusCode::FAILED_PRECONDITION);
        auto reset = named<V1::ResetPasswordRequest>(administrator);
        reset.set_revoke_keys(false);
        REQUIRE(call<V1::ResetPasswordResponse>(
                    *stub, &Stub::ResetPassword, reset, adminToken)
                .first.error_code() == grpc::StatusCode::FAILED_PRECONDITION);
        REQUIRE(seeder.isAdministrator(administrator));
        REQUIRE_FALSE(seeder.isProvisional(administrator));
    }
}
