#include "UnsupportedBackends.h"

namespace epdn {

UnsupportedIdentityBackend::UnsupportedIdentityBackend(
    SecurityClass declaredClass)
    : declaredClass_(declaredClass) {}
bool UnsupportedIdentityBackend::begin() { return false; }
SecurityClass UnsupportedIdentityBackend::securityClass() const {
  return declaredClass_;
}
bool UnsupportedIdentityBackend::getDeviceId(uint8_t *, size_t, size_t &l) {
  l = 0;
  return false;
}
bool UnsupportedIdentityBackend::getPublicKey(uint8_t *, size_t, size_t &l) {
  l = 0;
  return false;
}
bool UnsupportedIdentityBackend::createDeterministicProof(
    const uint8_t *, size_t, uint8_t *, size_t, size_t &l) {
  l = 0;
  return false;
}
bool UnsupportedIdentityBackend::sign(const uint8_t *, size_t, uint8_t *,
                                      size_t, size_t &l) {
  l = 0;
  return false;
}
bool UnsupportedIdentityBackend::getAttestation(const uint8_t *, size_t,
                                                uint8_t *, size_t,
                                                size_t &l) {
  l = 0;
  return false;
}

IdentityProtectedStorage::IdentityProtectedStorage()
    : UnsupportedIdentityBackend(
          SecurityClass::L1_PROTECTED_SOFTWARE_IDENTITY) {}
IdentityATECC608::IdentityATECC608()
    : UnsupportedIdentityBackend(SecurityClass::L3_EXTERNAL_SECURE_ELEMENT) {}
IdentityPlatformAttestation::IdentityPlatformAttestation()
    : UnsupportedIdentityBackend(SecurityClass::L4_ATTESTED_PLATFORM) {}

}  // namespace epdn
