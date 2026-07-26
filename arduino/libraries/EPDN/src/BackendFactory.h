#pragma once

#include "IdentityBackend.h"

#define EPDN_BACKEND_NONE 255
#define EPDN_BACKEND_SOFTWARE_TEST 0
#define EPDN_BACKEND_PROTECTED_STORAGE 1
#define EPDN_BACKEND_ESP32_HARDWARE 2
#define EPDN_BACKEND_ATECC608 3
#define EPDN_BACKEND_PLATFORM_ATTESTATION 4

#if defined(EPDN_PRODUCTION_BUILD) && !defined(EPDN_IDENTITY_BACKEND)
#error "EPDN production builds must explicitly select an identity backend"
#elif defined(EPDN_PRODUCTION_BUILD) &&                                \
    ((EPDN_IDENTITY_BACKEND == EPDN_BACKEND_SOFTWARE_TEST) ||         \
     (EPDN_IDENTITY_BACKEND == EPDN_BACKEND_ESP32_HARDWARE))
#error "EPDN production builds must not enable an L0 development backend"
#endif

namespace epdn {

enum class IdentityBackendKind : uint8_t {
  NONE = EPDN_BACKEND_NONE,
  SOFTWARE_TEST = EPDN_BACKEND_SOFTWARE_TEST,
  PROTECTED_STORAGE = EPDN_BACKEND_PROTECTED_STORAGE,
  ESP32_HARDWARE = EPDN_BACKEND_ESP32_HARDWARE,
  ATECC608 = EPDN_BACKEND_ATECC608,
  PLATFORM_ATTESTATION = EPDN_BACKEND_PLATFORM_ATTESTATION,
};

// Returns exactly the requested backend. It never downgrades or falls back.
IdentityBackend *createIdentityBackend(IdentityBackendKind requested);

}  // namespace epdn
