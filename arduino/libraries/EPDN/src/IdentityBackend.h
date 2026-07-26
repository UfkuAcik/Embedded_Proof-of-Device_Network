#pragma once

#include <stddef.h>
#include <stdint.h>

#include "SecurityClass.h"

namespace epdn {

class IdentityBackend {
 public:
  virtual bool begin() = 0;

  virtual SecurityClass securityClass() const = 0;

  virtual bool getDeviceId(uint8_t *output, size_t outputCapacity,
                           size_t &outputLength) = 0;

  virtual bool getPublicKey(uint8_t *output, size_t outputCapacity,
                            size_t &outputLength) = 0;

  virtual bool createDeterministicProof(
      const uint8_t *challenge, size_t challengeLength, uint8_t *output,
      size_t outputCapacity, size_t &outputLength) = 0;

  virtual bool sign(const uint8_t *message, size_t messageLength,
                    uint8_t *signature, size_t signatureCapacity,
                    size_t &signatureLength) = 0;

  virtual bool getAttestation(const uint8_t *nonce, size_t nonceLength,
                              uint8_t *output, size_t outputCapacity,
                              size_t &outputLength) = 0;

  virtual ~IdentityBackend() = default;
};

}  // namespace epdn
