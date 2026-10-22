#include <chrono>
#include <cstddef>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <catch2/catch_test_macros.hpp>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/generic/callback_generic_service.h>
#include <grpcpp/generic/generic_stub.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/interceptor.h>
#include <grpcpp/support/slice.h>
#include <grpcpp/support/server_interceptor.h>
#include <grpcpp/support/status.h>
#include <grpcpp/support/stub_options.h>
#include "uEventAnalysisToolBackend/grpc/requestIdentifierInterceptor.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

// These run a real server on a loopback port: the interceptor's job is
// to rewrite metadata between the wire and the handler, and nothing short
// of a round trip shows both what the handler saw and what came back.
// A generic service stands in for a real one so no .proto is needed.

namespace
{

constexpr size_t maximumSize{128};

/// @brief A zero-length payload.  A default-constructed ByteBuffer is not
///        a message at all, and gRPC aborts on sending one.
grpc::ByteBuffer makeEmptyMessage()
{
    const grpc::Slice slice;
    return grpc::ByteBuffer{&slice, 1};
}

class Factory :
    public grpc::experimental::ServerInterceptorFactoryInterface
{
public:
    grpc::experimental::Interceptor *
    CreateServerInterceptor(grpc::experimental::ServerRpcInfo *) override
    {
        return new RequestIdentifierInterceptor(maximumSize);
    }
};

/// @brief Answers every call with an empty message and records the
///        x-request-id the handler was handed.
class RecordingService : public grpc::CallbackGenericService
{
public:
    grpc::ServerGenericBidiReactor *
    CreateReactor(grpc::GenericCallbackServerContext *context) override
    {
        {
        const std::scoped_lock lock{mMutex};
        const auto &metadata = context->client_metadata();
        auto [first, last] = metadata.equal_range("x-request-id");
        mSeen.clear();
        for (auto idx = first; idx != last; ++idx)
        {
            mSeen.emplace_back(idx->second.data(), idx->second.size());
        }
        }
        return new Reactor;
    }
    [[nodiscard]] std::vector<std::string> seen() const
    {
        const std::scoped_lock lock{mMutex};
        return mSeen;
    }
private:
    class Reactor : public grpc::ServerGenericBidiReactor
    {
    public:
        Reactor()
        {
            StartWriteAndFinish(&mResponse, grpc::WriteOptions{},
                                grpc::Status::OK);
        }
        void OnDone() override
        {
            delete this;
        }
    private:
        grpc::ByteBuffer mResponse{makeEmptyMessage()};
    };
    mutable std::mutex mMutex;
    std::vector<std::string> mSeen;
};

/// @brief What one round trip looked like from both ends.
struct RoundTrip
{
    grpc::Status status;
    std::vector<std::string> seenByHandler;
    std::vector<std::string> returnedToClient;
};

class TestServer
{
public:
    TestServer()
    {
        grpc::ServerBuilder builder;
        int port{0};
        builder.AddListeningPort("127.0.0.1:0",
                                 grpc::InsecureServerCredentials(),
                                 &port);
        builder.RegisterCallbackGenericService(&mService);
        std::vector
        <
            std::unique_ptr<grpc::experimental::ServerInterceptorFactoryInterface>
        > creators;
        creators.push_back(std::make_unique<Factory> ());
        builder.experimental().SetInterceptorCreators(std::move(creators));
        mServer = builder.BuildAndStart();
        if (mServer == nullptr || port == 0)
        {
            throw std::runtime_error("Could not start the test server");
        }
        mChannel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port),
                                       grpc::InsecureChannelCredentials());
    }
    ~TestServer()
    {
        mServer->Shutdown(std::chrono::system_clock::now()
                        + std::chrono::seconds {1});
    }
    TestServer(const TestServer &) = delete;
    TestServer& operator=(const TestServer &) = delete;

    /// @param[in] identifier  The x-request-id to send, if any.
    RoundTrip call(const std::optional<std::string> &identifier)
    {
        grpc::GenericStub stub{mChannel};
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now()
                           + std::chrono::seconds {5});
        if (identifier)
        {
            context.AddMetadata("x-request-id", *identifier);
        }
        const grpc::ByteBuffer request{makeEmptyMessage()};
        grpc::ByteBuffer response;
        std::promise<grpc::Status> done;
        stub.UnaryCall(&context, "/ueat.test.Recording/Record",
                       grpc::StubOptions{}, &request, &response,
                       [&done](const grpc::Status &status)
                       {
                           done.set_value(status);
                       });
        RoundTrip result;
        result.status = done.get_future().get();
        result.seenByHandler = mService.seen();
        const auto &metadata = context.GetServerInitialMetadata();
        auto [first, last] = metadata.equal_range("x-request-id");
        for (auto idx = first; idx != last; ++idx)
        {
            result.returnedToClient.emplace_back(idx->second.data(),
                                                 idx->second.size());
        }
        return result;
    }
private:
    RecordingService mService;
    std::unique_ptr<grpc::Server> mServer;
    std::shared_ptr<grpc::Channel> mChannel;
};

/// @result True if this looks like what makeIdentifier produces: a
///         canonical, version 7 UUID.
bool isVersion7UUID(const std::string &identifier)
{
    if (identifier.size() != 36){return false;}
    for (size_t i = 0; i < identifier.size(); ++i)
    {
        const char c{identifier[i]};
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (c != '-'){return false;}
        }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        {
            return false;
        }
    }
    return identifier[14] == '7';
}

/// @brief The handler and the client both saw exactly one identifier,
///        and it was the same one.
std::string requireOneConsistentIdentifier(const RoundTrip &trip)
{
    REQUIRE(trip.status.ok());
    REQUIRE(trip.seenByHandler.size() == 1);
    REQUIRE(trip.returnedToClient.size() == 1);
    REQUIRE(trip.seenByHandler.front() == trip.returnedToClient.front());
    return trip.seenByHandler.front();
}

}

TEST_CASE("UEventAnalysisToolBackend::GRPC::RequestIdentifierInterceptor",
          "RequestIdentifierInterceptor")
{
    SECTION("Maximum identifier size must be positive")
    {
        REQUIRE_THROWS_AS(RequestIdentifierInterceptor{0},
                          std::invalid_argument);
    }

    TestServer server;

    SECTION("A client identifier is passed to the handler and echoed back")
    {
        const std::string identifier{"evid amplitudes request for sam-i-am"};
        REQUIRE(requireOneConsistentIdentifier(server.call(identifier))
                == identifier);
    }
    SECTION("An identifier of exactly the maximum size is kept")
    {
        const std::string identifier(maximumSize, 'x');
        REQUIRE(requireOneConsistentIdentifier(server.call(identifier))
                == identifier);
    }
    SECTION("No identifier: one is generated for the handler and the client")
    {
        const auto identifier
            = requireOneConsistentIdentifier(server.call(std::nullopt));
        REQUIRE(isVersion7UUID(identifier));
    }
    SECTION("Unacceptable identifiers are replaced, not duplicated")
    {
        // The original must be erased, not merely shadowed: the handler
        // would otherwise see two x-request-ids.
        for (const auto &bad : {std::string{""},
                                      std::string{"     "},
                                      std::string(maximumSize + 1, 'x')})
        {
            const auto identifier
                = requireOneConsistentIdentifier(server.call(bad));
            REQUIRE(identifier != bad);
            REQUIRE(isVersion7UUID(identifier));
        }
    }
    SECTION("Generated identifiers differ and sort by time")
    {
        const auto first
            = requireOneConsistentIdentifier(server.call(std::nullopt));
        const auto second
            = requireOneConsistentIdentifier(server.call(std::nullopt));
        REQUIRE(first != second);
        // Calls from one thread are strictly ordered, but the server may
        // generate on different threads; the millisecond prefix is not.
        REQUIRE(first.substr(0, 13) <= second.substr(0, 13));
    }
}
