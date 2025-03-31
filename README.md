Compiled on my ARM MacBook with this command: 

g++ -std=c++20 -o crypto_examples \
  main.cpp crypto_utils.cpp hash.cpp salt.cpp hmac.cpp keypair.cpp \
  asymmetric_crypto.cpp signature.cpp symmetric_crypto.cpp \
  -I/opt/homebrew/opt/openssl/include \
  -L/opt/homebrew/opt/openssl/lib \
  -lcrypto