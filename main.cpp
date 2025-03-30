#include "crypto_utils.h"
#include "hash.h"
#include "salt.h"
#include "hmac.h"
#include "keypair.h"
#include "asymmetric_crypto.h"
#include "signature.h"
#include "symmetric_crypto.h"

#include <iostream>
#include <vector>
#include <format>
#include <string_view>

int main() {
    // Initialize OpenSSL
    initOpenSSL();
    
    try {
        std::cout << std::format("===== OpenSSL Cryptography Examples (C++20) =====\n\n");
        
        // 1. Basic Hashing
        std::cout << std::format("1. Basic Hashing Example:\n");
        std::string_view password = "hi-mom!";
        
        try {
            std::string hash1 = crypto::hashSHA256(password);
            
            std::cout << std::format("SHA-256 hash of '{}': {}\n", password, hash1);
            
            std::string hash2 = crypto::hashSHA256(password);
            bool match = hash1 == hash2;
            std::cout << std::format("Hashes match: {}\n\n", match ? "Yes ✓" : "No ✗");
        } catch (const std::exception& e) {
            std::cout << "Error in hashing: " << e.what() << "\n\n";
        }
        
        // 2. Password with Salt
        std::cout << std::format("2. Password with Salt Example:\n");
        std::vector<crypto::User> users;
        
        try {
            crypto::User user = crypto::signup("user@example.com", "secret123", users);
            std::cout << std::format("User created with salted password: {}\n", user.password);
            
            std::string loginResult = crypto::login("user@example.com", "secret123", users);
            std::cout << std::format("Login attempt with correct password: {}\n", loginResult);
            
            std::string loginFailResult = crypto::login("user@example.com", "wrongpassword", users);
            std::cout << std::format("Login attempt with wrong password: {}\n", loginFailResult);
        } catch (const std::exception& e) {
            std::cout << "Error in password salting: " << e.what() << "\n";
        }
        std::cout << "\n";
        
        // 3. HMAC Example
        std::cout << std::format("3. HMAC Example:\n");
        std::string_view key = "super-secret!";
        std::string_view message = "boo 👻";
        
        try {
            std::string hmac = crypto::createHMAC(key, message);
            std::cout << std::format("HMAC of message '{}' with key '{}': {}\n", message, key, hmac);
            
            std::string_view key2 = "other-password";
            std::string hmac2 = crypto::createHMAC(key2, message);
            std::cout << std::format("HMAC with different key '{}': {}\n", key2, hmac2);
        } catch (const std::exception& e) {
            std::cout << "Error in HMAC: " << e.what() << "\n";
        }
        std::cout << "\n";
        
        // 4. RSA Keypair Generation
        std::cout << std::format("4. RSA Keypair Generation Example:\n");
        
        try {
            crypto::KeyPair keys = crypto::generateKeyPair();
            
            std::cout << std::format("Public Key (truncated):\n{}\n", 
                keys.publicKey.substr(0, 100) + "...");
            std::cout << std::format("Private Key (truncated):\n{}\n", 
                keys.privateKey.substr(0, 100) + "...");
                
            // 5. Asymmetric Encryption
            std::cout << std::format("\n5. Asymmetric Encryption Example:\n");
            std::string_view secretMessage = "the british are coming!";
            
            std::string encrypted = crypto::publicEncrypt(keys.publicKey, secretMessage);
            std::cout << std::format("Original message: {}\n", secretMessage);
            std::cout << std::format("Encrypted: {}\n", encrypted);
            
            std::string decrypted = crypto::privateDecrypt(keys.privateKey, encrypted);
            std::cout << std::format("Decrypted: {}\n", decrypted);
            
            // 6. Digital Signature
            std::cout << std::format("\n6. Digital Signature Example:\n");
            std::string_view dataToSign = "this data must be signed";
            std::cout << std::format("Data to sign: {}\n", dataToSign);
            
            std::string signature = crypto::signMessage(keys.privateKey, dataToSign);
            std::cout << std::format("Signature: {}\n", signature);
            
            bool verified = crypto::verifySignature(keys.publicKey, dataToSign, signature);
            std::cout << std::format("Signature verified with correct data: {}\n", 
                verified ? "Yes ✓" : "No ✗");
            
            bool falsifiedVerified = crypto::verifySignature(keys.publicKey, "tampered data", signature);
            std::cout << std::format("Signature verified with tampered data: {}\n", 
                falsifiedVerified ? "Yes" : "No ✗");
        } catch (const std::exception& e) {
            std::cout << "Error in asymmetric cryptography: " << e.what() << "\n";
        }
        std::cout << "\n";
        
        // 7. Symmetric Encryption
        std::cout << std::format("7. Symmetric Encryption Example:\n");
        std::string_view plaintext = "i like turtles";
        std::cout << std::format("Original text: {}\n", plaintext);
        
        try {
            crypto::EncryptionResult result = crypto::encryptAES256(plaintext);
            std::cout << std::format("Encrypted: {}\n", result.encrypted);
            std::cout << std::format("Key: {}\n", bytesToHex(result.key));
            std::cout << std::format("IV: {}\n", bytesToHex(result.iv));
            
            std::string decryptedText = crypto::decryptAES256(result.encrypted, result.key, result.iv);
            std::cout << std::format("Decrypted: {}\n", decryptedText);
        } catch (const std::exception& e) {
            std::cout << "Error in symmetric encryption: " << e.what() << "\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
    }
    
    // Cleanup OpenSSL
    cleanupOpenSSL();
    
    return 0;
}