#include "hmac.h"
#include "crypto_utils.h"
#include <openssl/hmac.h>
#include <memory>
#include <stdexcept>

namespace crypto {

std::string createHMAC(std::string_view key, std::string_view message) {
    // Use EVP API instead of deprecated HMAC_* functions
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP context: " + getOpenSSLErrors());
    }
    
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new_mac_key(
        EVP_PKEY_HMAC, nullptr, 
        reinterpret_cast<const unsigned char*>(key.data()), 
        static_cast<int>(key.length())), 
        EVP_PKEY_free);
    
    if (!pkey) {
        throw std::runtime_error("Failed to create HMAC key: " + getOpenSSLErrors());
    }
    
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) {
        throw std::runtime_error("Failed to initialize HMAC: " + getOpenSSLErrors());
    }
    
    if (EVP_DigestSignUpdate(ctx.get(), message.data(), message.length()) != 1) {
        throw std::runtime_error("Failed to update HMAC: " + getOpenSSLErrors());
    }
    
    size_t hmac_len;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &hmac_len) != 1) {
        throw std::runtime_error("Failed to determine HMAC length: " + getOpenSSLErrors());
    }
    
    std::vector<unsigned char> hmac_value(hmac_len);
    if (EVP_DigestSignFinal(ctx.get(), hmac_value.data(), &hmac_len) != 1) {
        throw std::runtime_error("Failed to compute HMAC: " + getOpenSSLErrors());
    }
    
    hmac_value.resize(hmac_len);
    return bytesToHex(hmac_value);
}

bool verifyHMAC(std::string_view key, std::string_view message, std::string_view hmac) {
    try {
        std::string computedHmac = createHMAC(key, message);
        
        // Constant-time comparison to avoid timing attacks
        if (computedHmac.length() != hmac.length()) {
            return false;
        }
        
        unsigned char result = 0;
        for (size_t i = 0; i < computedHmac.length(); i++) {
            result |= computedHmac[i] ^ hmac[i];
        }
        
        return (result == 0);
    } catch (...) {
        return false;
    }
}

} // namespace crypto