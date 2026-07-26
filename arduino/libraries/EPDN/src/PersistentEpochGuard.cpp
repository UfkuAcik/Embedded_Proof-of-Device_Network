#include "PersistentEpochGuard.h"

#if defined(ARDUINO_ARCH_ESP32)
#include <Preferences.h>
#endif

namespace epdn {
namespace {

void encodeU64(uint64_t value, uint8_t output[8]) {
  for (int index = 7; index >= 0; --index) {
    output[index] = static_cast<uint8_t>(value);
    value >>= 8;
  }
}

uint64_t decodeU64(const uint8_t input[8]) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) {
    value = (value << 8) | input[index];
  }
  return value;
}

}  // namespace

PersistentEpochGuard::PersistentEpochGuard()
    : initialized_(false), hasLast_(false), lastEpoch_(0) {}

bool PersistentEpochGuard::begin() {
#if !defined(ARDUINO_ARCH_ESP32)
  return false;
#else
  Preferences preferences;
  if (!preferences.begin("epdn_ticket", true)) {
    // Read-only open also fails for a namespace that has never existed. A
    // write-capable open distinguishes that case from unavailable/broken NVS,
    // but no epoch value is put until reserve().
    Preferences createOrOpen;
    if (!createOrOpen.begin("epdn_ticket", false)) {
      return false;
    }
    const size_t existingLength =
        createOrOpen.getBytesLength("last_epoch");
    createOrOpen.end();
    if (existingLength != 0) {
      // A value that could not be read through the read-only path is not safe
      // to treat as pristine state.
      return false;
    }
    hasLast_ = false;
    lastEpoch_ = 0;
    initialized_ = true;
    return true;
  }
  uint8_t stored[8] = {0};
  const size_t length = preferences.getBytesLength("last_epoch");
  hasLast_ = length == sizeof(stored) &&
             preferences.getBytes("last_epoch", stored, sizeof(stored)) ==
                 sizeof(stored);
  preferences.end();
  if (length != 0 && !hasLast_) {
    return false;
  }
  if (hasLast_) {
    lastEpoch_ = decodeU64(stored);
  }
  initialized_ = true;
  return true;
#endif
}

bool PersistentEpochGuard::reserve(uint64_t epoch) {
#if !defined(ARDUINO_ARCH_ESP32)
  (void)epoch;
  return false;
#else
  if (!initialized_ || (hasLast_ && epoch <= lastEpoch_)) {
    return false;
  }
  uint8_t encoded[8] = {0};
  encodeU64(epoch, encoded);
  Preferences preferences;
  if (!preferences.begin("epdn_ticket", false)) {
    return false;
  }
  // Exactly one small write per newly reserved epoch; retries reuse RAM.
  const bool written =
      preferences.putBytes("last_epoch", encoded, sizeof(encoded)) ==
      sizeof(encoded);
  preferences.end();
  if (written) {
    lastEpoch_ = epoch;
    hasLast_ = true;
  }
  return written;
#endif
}

bool PersistentEpochGuard::isReserved(uint64_t epoch) const {
  return initialized_ && hasLast_ && epoch <= lastEpoch_;
}

}  // namespace epdn
