#include "IdentitySoftwareTest.h"

namespace epdn {

IdentitySoftwareTest::IdentitySoftwareTest() : delegate_("epdn_sw_test") {}
bool IdentitySoftwareTest::begin() { return delegate_.begin(); }
SecurityClass IdentitySoftwareTest::securityClass() const {
  return SecurityClass::L0_SOFTWARE_TEST;
}
bool IdentitySoftwareTest::getDeviceId(uint8_t *o, size_t c, size_t &l) {
  return delegate_.getDeviceId(o, c, l);
}
bool IdentitySoftwareTest::getPublicKey(uint8_t *o, size_t c, size_t &l) {
  return delegate_.getPublicKey(o, c, l);
}
bool IdentitySoftwareTest::createDeterministicProof(const uint8_t *m, size_t n,
                                                    uint8_t *o, size_t c,
                                                    size_t &l) {
  return delegate_.createDeterministicProof(m, n, o, c, l);
}
bool IdentitySoftwareTest::sign(const uint8_t *m, size_t n, uint8_t *o,
                                size_t c, size_t &l) {
  return delegate_.sign(m, n, o, c, l);
}
bool IdentitySoftwareTest::getAttestation(const uint8_t *n, size_t nl,
                                          uint8_t *o, size_t c, size_t &l) {
  return delegate_.getAttestation(n, nl, o, c, l);
}

}  // namespace epdn
