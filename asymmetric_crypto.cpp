#include "asymmetric_crypto.h"
#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <memory>
#include <stdexcept>

namespace crypto {

std::string publicEncrypt(std::string_view publicKey, std::string_view message) {
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
    
    // Create encryption context
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(pkey.get(), nullptr), 
        EVP_PKEY_CTX_free
    );
    
    if (!ctx) {
        throw std::runtime_error("Failed to create encryption context: " + getOpenSSLErrors());
    }
    
    if (EVP_PKEY_encrypt_init(ctx.get()) != 1) {
        throw std::runtime_error("Failed to initialize encryption: " + getOpenSSLErrors());
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
        throw std::runtime_error("Failed to set RSA padding: " + getOpenSSLErrors());
    }
    
    // Determine buffer length
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, 
                        reinterpret_cast<const unsigned char*>(message.data()), 
                        message.length()) != 1) {
        throw std::runtime_error("Failed to determine buffer length: " + getOpenSSLErrors());
    }
    
    // Allocate buffer for encrypted data
    std::vector<unsigned char> out(outlen);
    
    // Encrypt data
    if (EVP_PKEY_encrypt(ctx.get(), out.data(), &outlen, 
                        reinterpret_cast<const unsigned char*>(message.data()), 
                        message.length()) != 1) {
        throw std::runtime_error("Failed to encrypt data: " + getOpenSSLErrors());
    }
    
    // Resize buffer to actual length and convert to hex
    out.resize(outlen);
    return bytesToHex(out);
}

std::string privateDecrypt(std::string_view privateKey, std::string_view encryptedHex) {
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
    
    // Convert hex string to binary
    auto encryptedData = hexToBytes(encryptedHex);
    
    // Create decryption context
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(pkey.get(), nullptr), 
        EVP_PKEY_CTX_free
    );
    
    if (!ctx) {
        throw std::runtime_error("Failed to create decryption context: " + getOpenSSLErrors());
    }
    
    if (EVP_PKEY_decrypt_init(ctx.get()) != 1) {
        throw std::runtime_error("Failed to initialize decryption: " + getOpenSSLErrors());
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
        throw std::runtime_error("Failed to set RSA padding: " + getOpenSSLErrors());
    }
    
    // Determine buffer length
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, 
                        encryptedData.data(), encryptedData.size()) != 1) {
        throw std::runtime_error("Failed to determine buffer length: " + getOpenSSLErrors());
    }
    
    // Allocate buffer for decrypted data
    std::vector<unsigned char> out(outlen);
    
    // Decrypt data
    if (EVP_PKEY_decrypt(ctx.get(), out.data(), &outlen, 
                        encryptedData.data(), encryptedData.size()) != 1) {
        throw std::runtime_error("Failed to decrypt data: " + getOpenSSLErrors());
    }
    
    // Convert to string
    return std::string(reinterpret_cast<char*>(out.data()), outlen);
}

} // namespace crypto