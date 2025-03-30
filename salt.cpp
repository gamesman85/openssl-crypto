#include "salt.h"
#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <ranges>
#include <stdexcept>

namespace crypto {

std::string generateSalt(size_t length) {
    std::vector<unsigned char> salt(length);
    
    if (RAND_bytes(salt.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Failed to generate random bytes: " + getOpenSSLErrors());
    }
    
    return bytesToHex(salt);
}

std::string hashPasswordWithSalt(std::string_view password, std::string_view salt) {
    std::vector<unsigned char> derived_key(64);
    
    // Using a simplified version of scrypt parameters
    if (EVP_PBE_scrypt(
            password.data(), password.length(),
            reinterpret_cast<const unsigned char*>(salt.data()), salt.length(),
            16384, 8, 1, 0, derived_key.data(), derived_key.size()) != 1) {
        throw std::runtime_error("Failed to hash password with salt: " + getOpenSSLErrors());
    }
    
    return bytesToHex(derived_key);
}

User signup(std::string_view email, std::string_view password, std::vector<User>& users) {
    std::string salt = generateSalt();
    std::string hashedPassword = hashPasswordWithSalt(password, salt);
    
    User user;
    user.email = std::string(email);
    user.password = salt + ":" + hashedPassword;
    
    users.push_back(user);
    return user;
}

std::string login(std::string_view email, std::string_view password, const std::vector<User>& users) {
    // Find user
    auto userIt = std::ranges::find_if(users, [&email](const User& u) {
        return u.email == email;
    });
    
    if (userIt == users.end()) {
        return "login fail!";
    }
    
    // Split salt and key
    const auto& storedPassword = userIt->password;
    size_t separatorPos = storedPassword.find(':');
    if (separatorPos == std::string::npos) {
        return "login fail!";
    }
    
    std::string_view salt = std::string_view(storedPassword).substr(0, separatorPos);
    std::string_view storedHash = std::string_view(storedPassword).substr(separatorPos + 1);
    
    // Hash the provided password with the stored salt
    std::string hashedPassword = hashPasswordWithSalt(password, salt);
    
    // Timing-safe comparison
    if (storedHash.length() != hashedPassword.length()) {
        return "login fail!";
    }
    
    // Constant-time comparison to avoid timing attacks
    unsigned char result = 0;
    for (size_t i = 0; i < storedHash.length(); i++) {
        result |= storedHash[i] ^ hashedPassword[i];
    }
    
    return (result == 0) ? "login success!" : "login fail!";
}

} // namespace crypto