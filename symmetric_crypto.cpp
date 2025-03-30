#include "symmetric_crypto.h"
#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <memory>
#include <stdexcept>

namespace crypto {

EncryptionResult encryptAES256(std::string_view plaintext) {
    EncryptionResult result;
    
    // Generate random key and IV
    result.key.resize(32); // 256 bits
    result.iv.resize(16);  // 128 bits
    
    if (RAND_bytes(result.key.data(), static_cast<int>(result.key.size())) != 1 ||
        RAND_bytes(result.iv.data(), static_cast<int>(result.iv.size())) != 1) {
        throw std::runtime_error("Failed to generate random bytes: " + getOpenSSLErrors());
    }
    
    // Encrypt the data
    result.encrypted = encryptAES256WithKey(plaintext, result.key, result.iv);
    return result;
}

std::string encryptAES256WithKey(
    std::string_view plaintext,
    std::span<const unsigned char> key,
    std::span<const unsigned char> iv
) {
    if (key.size() != 32) {
        throw std::runtime_error("Invalid key size for AES-256. Expected 32 bytes.");
    }
    
    if (iv.size() != 16) {
        throw std::runtime_error("Invalid IV size for AES-256. Expected 16 bytes.");
    }
    
    // Create and initialize encryption context
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free
    );
    
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLErrors());
    }
    
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("Failed to initialize encryption: " + getOpenSSLErrors());
    }
    
    // Allocate buffer for encrypted data (plaintext length + block size for padding)
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int ciphertext_len = 0;
    int len = 0;
    
    // Encrypt data
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, 
                         reinterpret_cast<const unsigned char*>(plaintext.data()), 
                         static_cast<int>(plaintext.length())) != 1) {
        throw std::runtime_error("Failed to encrypt data: " + getOpenSSLErrors());
    }
    
    ciphertext_len += len;
    
    // Finalize encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + ciphertext_len, &len) != 1) {
        throw std::runtime_error("Failed to finalize encryption: " + getOpenSSLErrors());
    }
    
    ciphertext_len += len;
    
    // Resize ciphertext to actual length and convert to hex
    ciphertext.resize(ciphertext_len);
    return bytesToHex(ciphertext);
}

std::string decryptAES256(
    std::string_view ciphertextHex,
    std::span<const unsigned char> key,
    std::span<const unsigned char> iv
) {
    if (key.size() != 32) {
        throw std::runtime_error("Invalid key size for AES-256. Expected 32 bytes.");
    }
    
    if (iv.size() != 16) {
        throw std::runtime_error("Invalid IV size for AES-256. Expected 16 bytes.");
    }
    
    // Convert hex to binary
    auto ciphertext = hexToBytes(ciphertextHex);
    
    // Create and initialize decryption context
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free
    );
    
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLErrors());
    }
    
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("Failed to initialize decryption: " + getOpenSSLErrors());
    }
    
    // Allocate buffer for decrypted data
    std::vector<unsigned char> plaintext(ciphertext.size());
    int plaintext_len = 0;
    int len = 0;
    
    // Decrypt data
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, 
                         ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("Failed to decrypt data: " + getOpenSSLErrors());
    }
    
    plaintext_len += len;
    
    // Finalize decryption (handle padding)
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintext_len, &len) != 1) {
        throw std::runtime_error("Failed to finalize decryption: " + getOpenSSLErrors());
    }
    
    plaintext_len += len;
    
    // Resize plaintext to actual length and convert to string
    plaintext.resize(plaintext_len);
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
}

} // namespace crypto