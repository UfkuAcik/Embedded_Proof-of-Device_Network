#pragma once

#include <stdint.h>

namespace epdn {

class PersistentEpochGuard {
 public:
  PersistentEpochGuard();
  bool begin();
  bool reserve(uint64_t epoch);
  bool isReserved(uint64_t epoch) const;

 private:
  bool initialized_;
  bool hasLast_;
  uint64_t lastEpoch_;
};

}  // namespace epdn
