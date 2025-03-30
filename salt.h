#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace crypto {

struct User {
    std::string email;
    std::string password; // Will store "salt:hashedPassword"
};

// Generate random salt
std::string generateSalt(size_t length = 16);

// Hash password with salt using scrypt
std::string hashPasswordWithSalt(std::string_view password, std::string_view salt);

// Register new user
User signup(std::string_view email, std::string_view password, std::vector<User>& users);

// Attempt login - returns success message
std::string login(std::string_view email, std::string_view password, const std::vector<User>& users);

} // namespace crypto