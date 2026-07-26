#include "SecurityClass.h"

namespace epdn {

const char *securityClassName(SecurityClass value) {
  switch (value) {
    case SecurityClass::L0_SOFTWARE_TEST:
      return "L0_SOFTWARE_TEST";
    case SecurityClass::L1_PROTECTED_SOFTWARE_IDENTITY:
      return "L1_PROTECTED_SOFTWARE_IDENTITY";
    case SecurityClass::L2_NATIVE_HARDWARE_IDENTITY:
      return "L2_NATIVE_HARDWARE_IDENTITY";
    case SecurityClass::L3_EXTERNAL_SECURE_ELEMENT:
      return "L3_EXTERNAL_SECURE_ELEMENT";
    case SecurityClass::L4_ATTESTED_PLATFORM:
      return "L4_ATTESTED_PLATFORM";
  }
  return "INVALID";
}

}  // namespace epdn
