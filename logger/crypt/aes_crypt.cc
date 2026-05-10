#include "crypt/aes_crypt.h"

#include "cryptopp/aes.h"
#include "cryptopp/base64.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/filters.h"
#include "cryptopp/gcm.h"
#include "cryptopp/hex.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"

// AES-GCM with random per-call IV (12 bytes).
// Wire format: [IV 12B][ciphertext][auth_tag 16B]
// GCM provides both confidentiality and integrity (authenticated encryption).

namespace logger {
namespace crypt {

namespace detail {
using CryptoPP::byte;

static constexpr size_t kIVSize = 12;   // GCM recommended IV length
static constexpr size_t kTagSize = 16;  // GCM authentication tag length

static std::string GenerateKey() {
  CryptoPP::AutoSeededRandomPool rnd;
  byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
  rnd.GenerateBlock(key, sizeof(key));
  return BinaryKeyToHex(std::string(reinterpret_cast<const char*>(key), sizeof(key)));
}

void Encrypt(const void* input, size_t input_size, std::string& output, const std::string& key) {
  // Generate a fresh random IV for every call — prevents ciphertext patterns.
  CryptoPP::AutoSeededRandomPool rnd;
  byte iv[kIVSize];
  rnd.GenerateBlock(iv, sizeof(iv));

  CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
  enc.SetKeyWithIV(reinterpret_cast<const byte*>(key.data()), key.size(), iv, kIVSize);

  std::string ciphertext;
  CryptoPP::AuthenticatedEncryptionFilter ef(enc, new CryptoPP::StringSink(ciphertext), false, kTagSize);
  ef.Put(reinterpret_cast<const byte*>(input), input_size);
  ef.MessageEnd();

  // Prepend IV so the decoder can reconstruct without any shared state.
  output.clear();
  output.reserve(kIVSize + ciphertext.size());
  output.append(reinterpret_cast<const char*>(iv), kIVSize);
  output.append(ciphertext);
}

static std::string Decrypt(const void* data, size_t size, const std::string& key) {
  if (size < kIVSize + kTagSize) {
    return "";
  }
  const byte* bytes = reinterpret_cast<const byte*>(data);

  CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
  dec.SetKeyWithIV(reinterpret_cast<const byte*>(key.data()), key.size(), bytes, kIVSize);

  std::string plaintext;
  // MAC_AT_END: auth tag is appended after ciphertext (CryptoPP default).
  CryptoPP::AuthenticatedDecryptionFilter df(
      dec, new CryptoPP::StringSink(plaintext),
      CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, kTagSize);
  df.Put(bytes + kIVSize, size - kIVSize);
  df.MessageEnd();  // throws HashVerificationFailed if tag mismatch (tamper detected)
  return plaintext;
}
}  // namespace detail

AESCrypt::AESCrypt(std::string key) {
  key_ = std::move(key);
}

void AESCrypt::Encrypt(const void* input, size_t input_size, std::string& output) {
  detail::Encrypt(input, input_size, output, key_);
}

std::string AESCrypt::Decrypt(const void* data, size_t size) {
  return detail::Decrypt(data, size, key_);
}

std::string AESCrypt::GenerateKey() {
  return detail::GenerateKey();
}

std::string AESCrypt::GenerateIV() {
  // IV is now generated internally per Encrypt call; this stub kept for API compat.
  CryptoPP::AutoSeededRandomPool rnd;
  CryptoPP::byte iv[detail::kIVSize];
  rnd.GenerateBlock(iv, sizeof(iv));
  return std::string(reinterpret_cast<const char*>(iv), sizeof(iv));
}

}  // namespace crypt
}  // namespace logger
