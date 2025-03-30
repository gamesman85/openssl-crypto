#include "crypto_utils.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdlib>

std::string bytesToHex(std::span<const unsigned char> data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<unsigned char> hexToBytes(std::string_view hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string_view byteString = hex.substr(i, 2);
        auto byte = static_cast<unsigned char>(std::stoi(std::string(byteString), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void initOpenSSL() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void cleanupOpenSSL() {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

std::string getOpenSSLErrors() {
    std::stringstream errorStream;
    unsigned long errorCode;
    
    while ((errorCode = ERR_get_error()) != 0) {
        char errorBuffer[256];
        ERR_error_string_n(errorCode, errorBuffer, sizeof(errorBuffer));
        errorStream << errorBuffer << std::endl;
    }
    
    return errorStream.str();
}