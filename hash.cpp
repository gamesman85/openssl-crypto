#include "hash.h"
#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <memory>
#include <stdexcept>

namespace crypto {

std::string hashSHA256(std::string_view input) {
    // Create EVP message digest context
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) {
        throw std::runtime_error("Failed to create message digest context: " + getOpenSSLErrors());
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx.get(), input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx.get(), hash, &hash_len) != 1) {
        throw std::runtime_error("Failed to compute digest: " + getOpenSSLErrors());
    }
    
    // Convert to base64 (like in the Node.js example)
    std::unique_ptr<BIO, decltype(&BIO_free_all)> b64(BIO_new(BIO_f_base64()), BIO_free_all);
    std::unique_ptr<BIO, decltype(&BIO_free_all)> bmem(BIO_new(BIO_s_mem()), BIO_free_all);
    b64.reset(BIO_push(b64.release(), bmem.release()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64.get(), hash, hash_len);
    BIO_flush(b64.get());
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64.get(), &bptr);
    
    std::string result(bptr->data, bptr->length);
    return result;
}

bool compareHashes(std::string_view input, std::string_view hash) {
    try {
        std::string computedHash = hashSHA256(input);
        return computedHash == hash;
    } catch (...) {
        return false;
    }
}

} // namespace crypto