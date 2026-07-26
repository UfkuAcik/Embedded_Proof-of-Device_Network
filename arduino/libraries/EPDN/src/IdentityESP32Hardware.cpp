#include "IdentityESP32Hardware.h"

#include <string.h>

#if defined(ARDUINO_ARCH_ESP32)
#include <Preferences.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#endif

namespace epdn {
namespace {

constexpr size_t kPrivateKeyBytes = 32;
constexpr size_t kCompressedPublicKeyBytes = 33;
constexpr size_t kRawSignatureBytes = 64;

}  // namespace

IdentityESP32Hardware::IdentityESP32Hardware(const char *nvsNamespace)
    : ready_(false), nvsNamespace_(nvsNamespace) {
#if defined(ARDUINO_ARCH_ESP32)
  mbedtls_ecp_keypair_init(&key_);
  mbedtls_entropy_init(&entropy_);
  mbedtls_ctr_drbg_init(&ctrDrbg_);
#endif
}

IdentityESP32Hardware::~IdentityESP32Hardware() {
#if defined(ARDUINO_ARCH_ESP32)
  mbedtls_ecp_keypair_free(&key_);
  mbedtls_ctr_drbg_free(&ctrDrbg_);
  mbedtls_entropy_free(&entropy_);
#endif
}

bool IdentityESP32Hardware::begin() {
#if !defined(ARDUINO_ARCH_ESP32)
  return false;
#else
  if (ready_) {
    return true;
  }
  if (nvsNamespace_ == nullptr || strlen(nvsNamespace_) == 0 ||
      strlen(nvsNamespace_) > 15) {
    return false;
  }

  static const unsigned char personalization[] = "EPDN_P256_DEV_ID_V1";
  if (mbedtls_ctr_drbg_seed(&ctrDrbg_, mbedtls_entropy_func, &entropy_,
                            personalization,
                            sizeof(personalization) - 1) != 0 ||
      mbedtls_ecp_group_load(&key_.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
    return false;
  }

  Preferences preferences;
  if (!preferences.begin(nvsNamespace_, false)) {
    return false;
  }

  uint8_t privateKey[kPrivateKeyBytes] = {0};
  const size_t storedLength = preferences.getBytesLength("p256_priv");
  bool ok = false;
  if (storedLength == kPrivateKeyBytes &&
      preferences.getBytes("p256_priv", privateKey, sizeof(privateKey)) ==
          sizeof(privateKey)) {
    ok = mbedtls_mpi_read_binary(&key_.d, privateKey, sizeof(privateKey)) == 0 &&
         mbedtls_ecp_check_privkey(&key_.grp, &key_.d) == 0 &&
         mbedtls_ecp_mul(&key_.grp, &key_.Q, &key_.d, &key_.grp.G,
                         mbedtls_ctr_drbg_random, &ctrDrbg_) == 0;
  } else if (storedLength == 0 &&
             mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &key_,
                                 mbedtls_ctr_drbg_random, &ctrDrbg_) == 0 &&
             mbedtls_mpi_write_binary(&key_.d, privateKey,
                                      sizeof(privateKey)) == 0) {
    // The only persistent write is initial key creation. Existing keys are
    // never rewritten, limiting flash wear and accidental identity rotation.
    ok = preferences.putBytes("p256_priv", privateKey, sizeof(privateKey)) ==
         sizeof(privateKey);
  }
  preferences.end();
  mbedtls_platform_zeroize(privateKey, sizeof(privateKey));
  ready_ = ok;
  return ready_;
#endif
}

SecurityClass IdentityESP32Hardware::securityClass() const {
  return SecurityClass::L0_SOFTWARE_TEST;
}

bool IdentityESP32Hardware::getPublicKey(uint8_t *output,
                                         size_t outputCapacity,
                                         size_t &outputLength) {
  outputLength = 0;
#if !defined(ARDUINO_ARCH_ESP32)
  (void)output;
  (void)outputCapacity;
  return false;
#else
  if (!ready_ || output == nullptr ||
      outputCapacity < kCompressedPublicKeyBytes) {
    return false;
  }
  size_t written = 0;
  if (mbedtls_ecp_point_write_binary(
          &key_.grp, &key_.Q, MBEDTLS_ECP_PF_COMPRESSED, &written, output,
          outputCapacity) != 0 ||
      written != kCompressedPublicKeyBytes) {
    return false;
  }
  outputLength = written;
  return true;
#endif
}

bool IdentityESP32Hardware::getDeviceId(uint8_t *output, size_t outputCapacity,
                                        size_t &outputLength) {
  outputLength = 0;
  if (output == nullptr || outputCapacity < 32) {
    return false;
  }
  uint8_t publicKey[kCompressedPublicKeyBytes] = {0};
  size_t publicKeyLength = 0;
  if (!getPublicKey(publicKey, sizeof(publicKey), publicKeyLength) ||
      !sha256Domain("EPDN_DEVICE_PUBLIC_KEY_V1", publicKey, publicKeyLength,
                    output)) {
    return false;
  }
  outputLength = 32;
  return true;
}

bool IdentityESP32Hardware::createDeterministicProof(
    const uint8_t *challenge, size_t challengeLength, uint8_t *output,
    size_t outputCapacity, size_t &outputLength) {
  outputLength = 0;
  if (challenge == nullptr || challengeLength == 0 || challengeLength > 512) {
    return false;
  }
  uint8_t digest[32] = {0};
  const bool hashed =
      sha256Domain("EPDN_PROOF_V1", challenge, challengeLength, digest);
  const bool signedOk =
      hashed && signDigest(digest, output, outputCapacity, outputLength);
#if defined(ARDUINO_ARCH_ESP32)
  mbedtls_platform_zeroize(digest, sizeof(digest));
#else
  memset(digest, 0, sizeof(digest));
#endif
  return signedOk;
}

bool IdentityESP32Hardware::sign(const uint8_t *message, size_t messageLength,
                                 uint8_t *signature,
                                 size_t signatureCapacity,
                                 size_t &signatureLength) {
  signatureLength = 0;
  if (message == nullptr || messageLength == 0 || messageLength > 8192) {
    return false;
  }
  uint8_t digest[32] = {0};
  if (messageLength == sizeof(digest)) {
    memcpy(digest, message, sizeof(digest));
  } else {
#if defined(ARDUINO_ARCH_ESP32)
    if (mbedtls_sha256_ret(message, messageLength, digest, 0) != 0) {
      return false;
    }
#else
    return false;
#endif
  }
  const bool ok =
      signDigest(digest, signature, signatureCapacity, signatureLength);
#if defined(ARDUINO_ARCH_ESP32)
  mbedtls_platform_zeroize(digest, sizeof(digest));
#else
  memset(digest, 0, sizeof(digest));
#endif
  return ok;
}

bool IdentityESP32Hardware::getAttestation(const uint8_t *nonce,
                                           size_t nonceLength, uint8_t *output,
                                           size_t outputCapacity,
                                           size_t &outputLength) {
  (void)nonce;
  (void)nonceLength;
  (void)output;
  (void)outputCapacity;
  outputLength = 0;
  // Fail closed: this development backend has no hardware attestation.
  return false;
}

bool IdentityESP32Hardware::sha256Domain(const char *domain,
                                         const uint8_t *data,
                                         size_t dataLength,
                                         uint8_t output[32]) const {
#if !defined(ARDUINO_ARCH_ESP32)
  (void)domain;
  (void)data;
  (void)dataLength;
  (void)output;
  return false;
#else
  if (domain == nullptr || data == nullptr || output == nullptr) {
    return false;
  }
  mbedtls_sha256_context context;
  mbedtls_sha256_init(&context);
  const bool ok =
      mbedtls_sha256_starts_ret(&context, 0) == 0 &&
      mbedtls_sha256_update_ret(
          &context, reinterpret_cast<const uint8_t *>(domain),
          strlen(domain)) == 0 &&
      mbedtls_sha256_update_ret(&context, data, dataLength) == 0 &&
      mbedtls_sha256_finish_ret(&context, output) == 0;
  mbedtls_sha256_free(&context);
  return ok;
#endif
}

bool IdentityESP32Hardware::signDigest(const uint8_t digest[32],
                                       uint8_t *signature,
                                       size_t signatureCapacity,
                                       size_t &signatureLength) {
  signatureLength = 0;
#if !defined(ARDUINO_ARCH_ESP32)
  (void)digest;
  (void)signature;
  (void)signatureCapacity;
  return false;
#else
  if (!ready_ || digest == nullptr || signature == nullptr ||
      signatureCapacity < kRawSignatureBytes) {
    return false;
  }
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  bool ok = mbedtls_ecdsa_sign_det(&key_.grp, &r, &s, &key_.d, digest, 32,
                                   MBEDTLS_MD_SHA256) == 0;
  if (ok) {
    ok = mbedtls_mpi_write_binary(&r, signature, 32) == 0 &&
         mbedtls_mpi_write_binary(&s, signature + 32, 32) == 0;
  }
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  if (!ok) {
    mbedtls_platform_zeroize(signature, signatureCapacity);
    return false;
  }
  signatureLength = kRawSignatureBytes;
  return true;
#endif
}

}  // namespace epdn
