#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_SECRET_FILE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_SECRET_FILE_HPP
#include <filesystem>
#include <fstream>
#include <ios>
#include <optional>
#include <system_error>
#include <sstream>
#include <stdexcept>
#include <string>
#include <boost/property_tree/ptree.hpp>

/// @file secretFile.hpp
/// @brief Reads a secret out of a file so it need not be written into the
///        configuration.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.

namespace
{
/// @brief Reads a secret from a file.
/// @param[in] path     The file holding the secret.
/// @param[in] setting  The setting that named it, for the error message.
/// @result The file's contents with surrounding whitespace removed.
/// @throws std::invalid_argument if the file does not exist or holds
///         nothing but whitespace.
/// @throws std::runtime_error if the file cannot be read.
[[nodiscard]] inline std::string readSecretFile(
    const std::filesystem::path &path,
    const std::string &setting)
{
    if (!std::filesystem::exists(path))
    {
        throw std::invalid_argument(setting + " names " + path.string()
                                  + ", which does not exist");
    }
    std::ifstream file(path);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open " + path.string()
                               + " named by " + setting);
    }
    std::stringstream stream;
    stream << file.rdbuf();
    const auto contents = stream.str();
    const auto first = contents.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
    {
        throw std::invalid_argument(setting + " names " + path.string()
                                  + ", which is empty");
    }
    const auto last = contents.find_last_not_of(" \t\r\n");
    return contents.substr(first, last - first + 1);
}

/// @brief Resolves a setting given either inline or as a file.
/// @param[in] propertyTree  The parsed initialization file.
/// @param[in] inlineKey     The setting holding the value itself.
/// @param[in] fileKey       The setting naming a file holding the value.
/// @result The value, or nullopt if neither setting is present.
/// @throws std::invalid_argument if BOTH are given.
///
/// @note Both being set is an error rather than a precedence rule.  The
///       two disagreeing is exactly the situation where guessing wrong
///       means running with the wrong credential, and a deployment
///       half-migrated from one form to the other should be told so at
///       startup instead of at the first query.
template<typename PropertyTree>
[[nodiscard]] std::optional<std::string> resolveSecret(
    const PropertyTree &propertyTree,
    const std::string &inlineKey,
    const std::string &fileKey)
{
    auto inlineValue = propertyTree.template get_optional<std::string> (inlineKey);
    auto fileValue = propertyTree.template get_optional<std::string> (fileKey);
    if (inlineValue && fileValue)
    {
        throw std::invalid_argument("Both " + inlineKey + " and " + fileKey
                                  + " are set - use one");
    }
    if (fileValue)
    {
        return ::readSecretFile(*fileValue, fileKey);
    }
    if (inlineValue){return std::make_optional<std::string> (*inlineValue);}
    return std::nullopt;
}

}
#endif
