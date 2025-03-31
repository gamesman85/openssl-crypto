#include "keypair.h"
#include "crypto_utils.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <fstream>
#include <sstream>
#include <memory>
#include <stdexcept>

namespace crypto {

KeyPair generateKeyPair(int bits) {
    KeyPair keyPair;
    
    // Generate key pair with smart pointers for auto cleanup
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), EVP_PKEY_free);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), 
        EVP_PKEY_CTX_free
    );
    
    if (!pkey || !ctx) {
        throw std::runtime_error("Failed to create key objects: " + getOpenSSLErrors());
    }
    
    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw std::runtime_error("Failed to initialize key generation: " + getOpenSSLErrors());
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
        throw std::runtime_error("Failed to set RSA key size: " + getOpenSSLErrors());
    }
    
    EVP_PKEY* pkey_ptr = pkey.get();
    if (EVP_PKEY_keygen(ctx.get(), &pkey_ptr) != 1) {
        throw std::runtime_error("Failed to generate key pair: " + getOpenSSLErrors());
    }
    
    // Get public key in PEM format
    std::unique_ptr<BIO, decltype(&BIO_free_all)> pubBio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (!pubBio || PEM_write_bio_PUBKEY(pubBio.get(), pkey.get()) != 1) {
        throw std::runtime_error("Failed to write public key: " + getOpenSSLErrors());
    }
    
    BUF_MEM* pubPtr;
    BIO_get_mem_ptr(pubBio.get(), &pubPtr);
    keyPair.publicKey = std::string(pubPtr->data, pubPtr->length);
    
    // Get private key in PEM format
    std::unique_ptr<BIO, decltype(&BIO_free_all)> privBio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (!privBio || PEM_write_bio_PrivateKey(privBio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw std::runtime_error("Failed to write private key: " + getOpenSSLErrors());
    }
    
    BUF_MEM* privPtr;
    BIO_get_mem_ptr(privBio.get(), &privPtr);
    keyPair.privateKey = std::string(privPtr->data, privPtr->length);
    
    return keyPair;
}

void saveKeyPairToFiles(
    const KeyPair& keyPair, 
    const std::filesystem::path& publicKeyFile, 
    const std::filesystem::path& privateKeyFile
) {
    std::ofstream pubFile(publicKeyFile);
    if (!pubFile) {
        throw std::runtime_error("Failed to open public key file for writing");
    }
    pubFile << keyPair.publicKey;
    pubFile.close();
    
    std::ofstream privFile(privateKeyFile);
    if (!privFile) {
        throw std::runtime_error("Failed to open private key file for writing");
    }
    privFile << keyPair.privateKey;
    privFile.close();
}

KeyPair loadKeyPairFromFiles(
    const std::filesystem::path& publicKeyFile, 
    const std::filesystem::path& privateKeyFile
) {
    KeyPair keyPair;
    
    if (!std::filesystem::exists(publicKeyFile)) {
        throw std::runtime_error("Public key file does not exist");
    }
    
    if (!std::filesystem::exists(privateKeyFile)) {
        throw std::runtime_error("Private key file does not exist");
    }
    
    std::ifstream pubFile(publicKeyFile);
    if (!pubFile) {
        throw std::runtime_error("Failed to open public key file");
    }
    std::stringstream pubBuffer;
    pubBuffer << pubFile.rdbuf();
    keyPair.publicKey = pubBuffer.str();
    
    std::ifstream privFile(privateKeyFile);
    if (!privFile) {
        throw std::runtime_error("Failed to open private key file");
    }
    std::stringstream privBuffer;
    privBuffer << privFile.rdbuf();
    keyPair.privateKey = privBuffer.str();
    
    return keyPair;
}

} // namespace crypto