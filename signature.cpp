#include "signature.h"
#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <memory>
#include <stdexcept>

namespace crypto {

std::string signMessage(std::string_view privateKey, std::string_view message) {
    // Create BIO from memory buffer containing the private key
    std::unique_ptr<BIO, decltype(&BIO_free)> keyBio(
        BIO_new_mem_buf(privateKey.data(), static_cast<int>(privateKey.size())),
        BIO_free
    );
    
    if (!keyBio) {
        throw std::runtime_error("Failed to create BIO: " + getOpenSSLErrors());
    }
    
    // Read private key from BIO
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free
    );
    
    if (!pkey) {
        throw std::runtime_error("Failed to read private key: " + getOpenSSLErrors());
    }
    
    // Create message digest context
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free
    );
    
    if (!mdctx) {
        throw std::runtime_error("Failed to create message digest context: " + getOpenSSLErrors());
    }
    
    // Initialize signing operation
    if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) {
        throw std::runtime_error("Failed to initialize signing: " + getOpenSSLErrors());
    }
    
    // Update with message data
    if (EVP_DigestSignUpdate(mdctx.get(), message.data(), message.length()) != 1) {
        throw std::runtime_error("Failed to update digest: " + getOpenSSLErrors());
    }
    
    // Determine buffer length
    size_t sig_len;
    if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sig_len) != 1) {
        throw std::runtime_error("Failed to determine signature length: " + getOpenSSLErrors());
    }
    
    // Allocate buffer for signature
    std::vector<unsigned char> sig(sig_len);
    
    // Get signature
    if (EVP_DigestSignFinal(mdctx.get(), sig.data(), &sig_len) != 1) {
        throw std::runtime_error("Failed to get signature: " + getOpenSSLErrors());
    }
    
    // Resize buffer to actual length and convert to hex
    sig.resize(sig_len);
    return bytesToHex(sig);
}

bool verifySignature(
    std::string_view publicKey, 
    std::string_view message, 
    std::string_view signatureHex
) {
    try {
        // Create BIO from memory buffer containing the public key
        std::unique_ptr<BIO, decltype(&BIO_free)> keyBio(
            BIO_new_mem_buf(publicKey.data(), static_cast<int>(publicKey.size())),
            BIO_free
        );
        
        if (!keyBio) {
            throw std::runtime_error("Failed to create BIO: " + getOpenSSLErrors());
        }
        
        // Read public key from BIO
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
            PEM_read_bio_PUBKEY(keyBio.get(), nullptr, nullptr, nullptr),
            EVP_PKEY_free
        );
        
        if (!pkey) {
            throw std::runtime_error("Failed to read public key: " + getOpenSSLErrors());
        }
        
        // Convert hex signature to binary
        auto signature = hexToBytes(signatureHex);
        
        // Create message digest context
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(
            EVP_MD_CTX_new(),
            EVP_MD_CTX_free
        );
        
        if (!mdctx) {
            throw std::runtime_error("Failed to create message digest context: " + getOpenSSLErrors());
        }
        
        // Initialize verification operation
        if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) {
            throw std::runtime_error("Failed to initialize verification: " + getOpenSSLErrors());
        }
        
        // Update with message data
        if (EVP_DigestVerifyUpdate(mdctx.get(), message.data(), message.length()) != 1) {
            throw std::runtime_error("Failed to update digest: " + getOpenSSLErrors());
        }
        
        // Verify signature
        int result = EVP_DigestVerifyFinal(mdctx.get(), signature.data(), signature.size());
        
        if (result < 0) {
            throw std::runtime_error("Error verifying signature: " + getOpenSSLErrors());
        }
        
        return result == 1;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace crypto