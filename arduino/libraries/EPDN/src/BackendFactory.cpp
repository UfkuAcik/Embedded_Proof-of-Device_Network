#include "BackendFactory.h"

#include "IdentityESP32Hardware.h"
#include "IdentitySoftwareTest.h"
#include "UnsupportedBackends.h"

namespace epdn {

IdentityBackend *createIdentityBackend(IdentityBackendKind requested) {
  static IdentitySoftwareTest softwareTest;
  static IdentityProtectedStorage protectedStorage;
  static IdentityESP32Hardware esp32Hardware;
  static IdentityATECC608 atecc608;
  static IdentityPlatformAttestation platformAttestation;

  switch (requested) {
    case IdentityBackendKind::SOFTWARE_TEST:
      return &softwareTest;
    case IdentityBackendKind::PROTECTED_STORAGE:
      return &protectedStorage;
    case IdentityBackendKind::ESP32_HARDWARE:
      return &esp32Hardware;
    case IdentityBackendKind::ATECC608:
      return &atecc608;
    case IdentityBackendKind::PLATFORM_ATTESTATION:
      return &platformAttestation;
    case IdentityBackendKind::NONE:
      return nullptr;
  }
  return nullptr;
}

}  // namespace epdn
