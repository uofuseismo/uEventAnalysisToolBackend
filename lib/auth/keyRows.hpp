#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_KEY_ROWS_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_KEY_ROWS_HPP
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <pqxx/pqxx>
#include "uEventAnalysisToolBackend/auth/userList.hpp"

namespace UEventAnalysisToolBackend::Auth::Detail
{

inline constexpr std::string_view KEY_COLUMNS{
    "key_name, algorithm, fingerprint,"
    " (EXTRACT(EPOCH FROM created) * 1000000)::BIGINT AS created_us,"
    " (EXTRACT(EPOCH FROM expires) * 1000000)::BIGINT AS expires_us,"
    " (EXTRACT(EPOCH FROM last_used) * 1000000)::BIGINT AS last_used_us,"
    " active,"
    " (EXTRACT(EPOCH FROM invalidated) * 1000000)::BIGINT AS invalidated_us,"
    " reason"};

inline void appendKey(
    const pqxx::row_ref &row,
    std::vector<UEventAnalysisToolBackend::Auth::ActiveKey> *activeKeys,
    std::vector<UEventAnalysisToolBackend::Auth::InactiveKey> *inactiveKeys)
{
    using namespace UEventAnalysisToolBackend::Auth;
    // Everything below throws on a value the backend does not know.
    // That is a deployment bug, so it surfaces as a server error.
    const auto requireEd25519 = [](const std::string &algorithm)
    {
        if (algorithm != "ed25519")
        {
            throw std::runtime_error("Unhandled key algorithm "
                                   + algorithm);
        }
    };   

    requireEd25519(row["algorithm"].as<std::string> ()); 
    if (row["active"].as<bool> ())
    {
        ActiveKey key; 
        key.setName(row["key_name"].as<std::string> ()); 
        key.setAlgorithm(ActiveKey::Algorithm::ed25519);
        key.setFingerprint(row["fingerprint"].as<std::string> ()); 
        key.setWhenRegistered(
            std::chrono::microseconds{row["created_us"].as<int64_t> ()});
        if (!row["expires_us"].is_null())
        {
            key.setExpiration(
                std::chrono::microseconds{row["expires_us"].as<int64_t> ()});
        }
        if (!row["last_used_us"].is_null())
        {
            key.setLastUsed(
                std::chrono::microseconds{row["last_used_us"].as<int64_t> ()});
        }
        activeKeys->push_back(std::move(key));
    }
    else 
    {    
        InactiveKey key; 
        key.setName(row["key_name"].as<std::string> ()); 
        key.setAlgorithm(InactiveKey::Algorithm::ed25519);
        key.setFingerprint(row["fingerprint"].as<std::string> ()); 
        key.setWhenRegistered(
            std::chrono::microseconds{row["created_us"].as<int64_t> ()});
        if (!row["last_used_us"].is_null())
        {
            key.setLastUsed(std::chrono::microseconds{
                row["last_used_us"].as<int64_t> ()});
        }
        key.setWhenInvalidated(
            std::chrono::microseconds{row["invalidated_us"].as<int64_t> ()});
        const auto reason = row["reason"].as<std::string> ();
        if (reason == "revoked")
        {    
            key.setReason(InactiveKey::Reason::Revoked);
        }
        else if (reason == "expired")
        {
            key.setReason(InactiveKey::Reason::Expired);
        }
        else
        {
            throw std::runtime_error("Unhandled key state " + reason);
        }
        inactiveKeys->push_back(std::move(key));
    }
}

}
#endif
