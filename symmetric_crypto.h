#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <span>

namespace crypto {

struct EncryptionResult {
    std::string encrypted;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
};

// Encrypt data using AES-256
EncryptionResult encryptAES256(std::string_view plaintext);

// Encrypt data using AES-256 with provided key and IV
std::string encryptAES256WithKey(
    std::string_view plaintext,
    std::span<const unsigned char> key,
    std::span<const unsigned char> iv
);

// Decrypt data using AES-256
std::string decryptAES256(
    std::string_view ciphertextHex,
    std::span<const unsigned char> key,
    std::span<const unsigned char> iv
);

} // namespace crypto