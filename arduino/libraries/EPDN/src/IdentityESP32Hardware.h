#pragma once

#include "IdentityBackend.h"

#if defined(ARDUINO_ARCH_ESP32)
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#endif

namespace epdn {

// Development identity for ESP32. The private scalar is persisted in NVS and is
// therefore deliberately reported as L0 until flash encryption, secure boot,
// key purpose, and debug policy are independently provisioned and attested.
class IdentityESP32Hardware final : public IdentityBackend {
 public:
  explicit IdentityESP32Hardware(const char *nvsNamespace = "epdn_dev_id");
  ~IdentityESP32Hardware() override;

  bool begin() override;
  SecurityClass securityClass() const override;
  bool getDeviceId(uint8_t *output, size_t outputCapacity,
                   size_t &outputLength) override;
  bool getPublicKey(uint8_t *output, size_t outputCapacity,
                    size_t &outputLength) override;
  bool createDeterministicProof(const uint8_t *challenge,
                                size_t challengeLength, uint8_t *output,
                                size_t outputCapacity,
                                size_t &outputLength) override;
  bool sign(const uint8_t *message, size_t messageLength, uint8_t *signature,
            size_t signatureCapacity, size_t &signatureLength) override;
  bool getAttestation(const uint8_t *nonce, size_t nonceLength,
                      uint8_t *output, size_t outputCapacity,
                      size_t &outputLength) override;

 private:
  bool signDigest(const uint8_t digest[32], uint8_t *signature,
                  size_t signatureCapacity, size_t &signatureLength);
  bool sha256Domain(const char *domain, const uint8_t *data, size_t dataLength,
                    uint8_t output[32]) const;
  bool ready_;
  const char *nvsNamespace_;
#if defined(ARDUINO_ARCH_ESP32)
  mbedtls_ecp_keypair key_;
  mbedtls_entropy_context entropy_;
  mbedtls_ctr_drbg_context ctrDrbg_;
#endif
};

}  // namespace epdn
