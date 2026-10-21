#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <utility>
#ifndef NDEBUG
#include <cassert>
#endif
#include <grpcpp/support/interceptor.h>
#include <grpcpp/support/string_ref.h>
#include <boost/uuid/time_generator_v7.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "uEventAnalysisToolBackend/grpc/requestIdentifierInterceptor.hpp"

using namespace UEventAnalysisToolBackend::GRPC;

namespace
{

[[nodiscard]] bool isAcceptable(const grpc::string_ref &metadata,
                                const size_t maximumLength)
{
    // Empty
    if (metadata.empty()){return false;}
    // Don't want to log really long identifiers
    if (metadata.size() > maximumLength){return false;}
    // Printable ASCII only: no tabs, newlines, or other control characters.
    auto printable
        = std::all_of(metadata.begin(), metadata.end(),
                      [](const auto c)
                      {
                          return c >= 0x20 && c <= 0x7E;
                      });
    if (!printable){return false;}
    // And not all blanks
    auto hasContent
        = std::any_of(metadata.begin(), metadata.end(),
                      [](const auto c)
                      {
                         return c != ' ';
                      });
    return hasContent;
}

[[nodiscard]] std::string makeIdentifier()
{
    thread_local boost::uuids::time_generator_v7 generator;
    return boost::uuids::to_string(generator());
}

}

RequestIdentifierInterceptor::RequestIdentifierInterceptor(
    const size_t maximumIdentifierSize) :
    grpc::experimental::Interceptor {}
{
    if (maximumIdentifierSize < 1)
    {
        throw std::invalid_argument("Maximum identifier size must be positive");
    }
    mMaximumIdentifierSize = maximumIdentifierSize;
}

void RequestIdentifierInterceptor::Intercept(
    grpc::experimental::InterceptorBatchMethods *methods)
{
    using grpc::experimental::InterceptionHookPoints;
    if (methods->QueryInterceptionHookPoint(
        InterceptionHookPoints::POST_RECV_INITIAL_METADATA))
    {
        auto *metadata = methods->GetRecvInitialMetadata();
#ifndef NDEBUG
        assert(metadata != nullptr); // Guaranteed by grpc by this point 
#endif
        auto idx = metadata->find("x-request-id");
        // Was the x-request-id set?
        if (idx != metadata->end() &&
            ::isAcceptable(idx->second, mMaximumIdentifierSize))
        {
            mIdentifier.assign(idx->second.data(), idx->second.size());
        }
        else
        {
            if (idx != metadata->end()){metadata->erase(idx);}
            mIdentifier = ::makeIdentifier();
            // string_refs into literal and into mIdentifier which lives as
            // long as the RPC.  Do not touch mIdentifier after this.
            metadata->emplace("x-request-id", mIdentifier);
        }
    }
    if (methods->QueryInterceptionHookPoint(
        InterceptionHookPoints::PRE_SEND_INITIAL_METADATA))
    {
         methods->GetSendInitialMetadata()->emplace("x-request-id", mIdentifier);
    }
    methods->Proceed();
}
