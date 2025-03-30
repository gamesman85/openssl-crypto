#pragma once

#include <string>
#include <string_view>

namespace crypto {

// SHA-256 hashing function (returns base64 encoding like in Node.js)
std::string hashSHA256(std::string_view input);

// Example function showing hash comparison
bool compareHashes(std::string_view input, std::string_view hash);

} // namespace crypto