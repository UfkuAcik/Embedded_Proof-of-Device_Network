#pragma once

#include "IdentityESP32Hardware.h"

namespace epdn {

class IdentitySoftwareTest final : public IdentityBackend {
 public:
  IdentitySoftwareTest();
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
  IdentityESP32Hardware delegate_;
};

}  // namespace epdn
