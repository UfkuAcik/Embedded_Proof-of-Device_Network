#pragma once

#include <Arduino.h>

#include "EPDNTicketEngine.h"
#include "IdentityBackend.h"
#include "Protocol.h"

namespace epdn {

enum class SubmissionResult : uint8_t {
  ACCEPTED = 0,
  ALREADY_RECORDED = 1,
  PERMANENTLY_REJECTED = 2,
  TRANSIENT_FAILURE = 3,
};

struct EPDNConfig {
  const char *validatorUrl = nullptr;
  const char *networkId = nullptr;
  IdentityBackend *identity = nullptr;
  bool production = false;
  uint32_t requestTimeoutMs = 5000;
};

class EPDNMiner {
 public:
  EPDNMiner();
  bool begin(const EPDNConfig &config);
  void process();

 private:
  bool fetchChallenge(uint8_t *output, size_t capacity, size_t &length);
  SubmissionResult submitPending();
  void scheduleRetry();
  void logEvent(const char *level, const char *event,
                const char *detail = nullptr) const;

  EPDNConfig config_;
  EPDNTicketEngine ticketEngine_;
  bool initialized_;
  uint32_t nextActionAt_;
  uint32_t retryDelayMs_;
  uint8_t pendingSubmission_[1024];
  size_t pendingLength_;
  uint64_t pendingEpoch_;
};

}  // namespace epdn
