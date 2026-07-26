#pragma once

#include "IdentityBackend.h"
#include "PersistentEpochGuard.h"
#include "Protocol.h"

namespace epdn {

enum class TicketEngineError : uint8_t {
  NONE = 0,
  NOT_INITIALIZED = 1,
  INVALID_CHALLENGE = 2,
  WRONG_NETWORK = 3,
  SECURITY_CLASS_MISMATCH = 4,
  FIRMWARE_ID_MISMATCH = 5,
  EPOCH_ALREADY_RESERVED = 6,
  BUILD_FAILED = 7,
  STATE_RESERVATION_FAILED = 8,
};

// Transport-neutral ticket engine shared by Wi-Fi and UART gateway miners.
class EPDNTicketEngine {
 public:
  EPDNTicketEngine();
  bool begin(IdentityBackend &identity, const char *networkId, bool production);
  bool createSubmission(const uint8_t *canonicalChallenge,
                        size_t challengeLength, uint8_t *output,
                        size_t outputCapacity, size_t &outputLength,
                        uint64_t &epochNumber,
                        bool allowCachedRetry = false);
  TicketEngineError lastError() const;

 private:
  IdentityBackend *identity_;
  const char *networkId_;
  bool initialized_;
  TicketEngineError lastError_;
  uint8_t firmwareId_[kHashBytes];
  bool hasRetryCache_;
  uint64_t cachedEpoch_;
  uint8_t cachedChallengeHash_[kHashBytes];
  uint8_t cachedSubmission_[1024];
  size_t cachedSubmissionLength_;
  PersistentEpochGuard epochGuard_;
};

}  // namespace epdn
