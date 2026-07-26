#pragma once

#include "IdentityBackend.h"

namespace epdn {

class UnsupportedIdentityBackend : public IdentityBackend {
 public:
  explicit UnsupportedIdentityBackend(SecurityClass declaredClass);
  bool begin() override;
  SecurityClass securityClass() const override;
  bool getDeviceId(uint8_t *, size_t, size_t &) override;
  bool getPublicKey(uint8_t *, size_t, size_t &) override;
  bool createDeterministicProof(const uint8_t *, size_t, uint8_t *, size_t,
                                size_t &) override;
  bool sign(const uint8_t *, size_t, uint8_t *, size_t, size_t &) override;
  bool getAttestation(const uint8_t *, size_t, uint8_t *, size_t,
                      size_t &) override;

 private:
  SecurityClass declaredClass_;
};

class IdentityProtectedStorage final : public UnsupportedIdentityBackend {
 public:
  IdentityProtectedStorage();
};
class IdentityATECC608 final : public UnsupportedIdentityBackend {
 public:
  IdentityATECC608();
};
class IdentityPlatformAttestation final : public UnsupportedIdentityBackend {
 public:
  IdentityPlatformAttestation();
};

}  // namespace epdn
