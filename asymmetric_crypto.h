#pragma once

#include <string>
#include <string_view>

namespace crypto {

// Encrypt message using public key
std::string publicEncrypt(std::string_view publicKey, std::string_view message);

// Decrypt message using private key
std::string privateDecrypt(std::string_view privateKey, std::string_view encryptedHex);

} // namespace crypto