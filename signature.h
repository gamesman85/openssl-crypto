#pragma once

#include <string>
#include <string_view>

namespace crypto {

// Sign a message using private key
std::string signMessage(std::string_view privateKey, std::string_view message);

// Verify a signature using public key
bool verifySignature(std::string_view publicKey, std::string_view message, std::string_view signatureHex);

} // namespace crypto