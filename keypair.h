#pragma once

#include <string>
#include <filesystem>

namespace crypto {

struct KeyPair {
    std::string publicKey;
    std::string privateKey;
};

// Generate RSA key pair
KeyPair generateKeyPair(int bits = 2048);

// Save keys to files
void saveKeyPairToFiles(
    const KeyPair& keyPair, 
    const std::filesystem::path& publicKeyFile, 
    const std::filesystem::path& privateKeyFile
);

// Load keys from files
KeyPair loadKeyPairFromFiles(
    const std::filesystem::path& publicKeyFile, 
    const std::filesystem::path& privateKeyFile
);

} // namespace crypto