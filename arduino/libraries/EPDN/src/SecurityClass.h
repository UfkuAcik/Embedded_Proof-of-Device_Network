#pragma once

#include <stdint.h>

namespace epdn {

enum class SecurityClass : uint8_t {
  L0_SOFTWARE_TEST = 0,
  L1_PROTECTED_SOFTWARE_IDENTITY = 1,
  L2_NATIVE_HARDWARE_IDENTITY = 2,
  L3_EXTERNAL_SECURE_ELEMENT = 3,
  L4_ATTESTED_PLATFORM = 4,
};

const char *securityClassName(SecurityClass value);

}  // namespace epdn
