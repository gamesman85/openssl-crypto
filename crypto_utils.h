#pragma once

#include <string>
#include <vector>
#include <span>

// Convert binary data to hex string
std::string bytesToHex(std::span<const unsigned char> data);

// Convert hex string to binary
std::vector<unsigned char> hexToBytes(std::string_view hex);

// Initialize OpenSSL libraries
void initOpenSSL();

// Clean up OpenSSL resources
void cleanupOpenSSL();

// Print OpenSSL errors
std::string getOpenSSLErrors();