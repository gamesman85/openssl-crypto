#pragma once

#include <string>
#include <string_view>

namespace crypto {

// Create HMAC from message and key
std::string createHMAC(std::string_view key, std::string_view message);

// Verify HMAC
bool verifyHMAC(std::string_view key, std::string_view message, std::string_view hmac);

} // namespace crypto