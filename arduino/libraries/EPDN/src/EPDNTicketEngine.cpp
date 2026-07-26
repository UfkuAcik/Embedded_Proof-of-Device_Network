#include "EPDNTicketEngine.h"

#include <string.h>

namespace epdn {

EPDNTicketEngine::EPDNTicketEngine()
    : identity_(nullptr),
      networkId_(nullptr),
      initialized_(false),
      lastError_(TicketEngineError::NONE),
      hasRetryCache_(false),
      cachedEpoch_(0),
      cachedSubmissionLength_(0) {
  memset(firmwareId_, 0, sizeof(firmwareId_));
  memset(cachedChallengeHash_, 0, sizeof(cachedChallengeHash_));
  memset(cachedSubmission_, 0, sizeof(cachedSubmission_));
}

bool EPDNTicketEngine::begin(IdentityBackend &identity, const char *networkId,
                             bool production) {
  if (networkId == nullptr || strlen(networkId) == 0 ||
      strlen(networkId) > kMaxChainIdBytes ||
      (production &&
       identity.securityClass() == SecurityClass::L0_SOFTWARE_TEST) ||
      !developmentFirmwareId(firmwareId_) || !identity.begin() ||
      !epochGuard_.begin()) {
    lastError_ = TicketEngineError::NOT_INITIALIZED;
    return false;
  }
  identity_ = &identity;
  networkId_ = networkId;
  initialized_ = true;
  lastError_ = TicketEngineError::NONE;
  return true;
}

bool EPDNTicketEngine::createSubmission(const uint8_t *canonicalChallenge,
                                        size_t challengeLength,
                                        uint8_t *output,
                                        size_t outputCapacity,
                                        size_t &outputLength,
                                        uint64_t &epochNumber,
                                        bool allowCachedRetry) {
  outputLength = 0;
  epochNumber = 0;
  EpochChallengeView challenge{};
  uint8_t ticket[kHashBytes] = {0};
  uint8_t challengeHash[kHashBytes] = {0};
  if (!initialized_) {
    lastError_ = TicketEngineError::NOT_INITIALIZED;
    return false;
  }
  if (!parseEpochChallenge(canonicalChallenge, challengeLength, challenge)) {
    lastError_ = TicketEngineError::INVALID_CHALLENGE;
    return false;
  }
  if (strcmp(challenge.chainId, networkId_) != 0) {
    lastError_ = TicketEngineError::WRONG_NETWORK;
    return false;
  }
  if (challenge.securityClass != identity_->securityClass()) {
    lastError_ = TicketEngineError::SECURITY_CLASS_MISMATCH;
    return false;
  }
  if (!constantTimeEqual(challenge.approvedFirmwareId, firmwareId_,
                         sizeof(firmwareId_))) {
    lastError_ = TicketEngineError::FIRMWARE_ID_MISMATCH;
    return false;
  }
  const uint8_t *challengeParts[] = {canonicalChallenge};
  const size_t challengePartLengths[] = {challengeLength};
  if (!hashDomain("EPDN_CHALLENGE_ID_V1", challengeParts,
                  challengePartLengths, 1, challengeHash)) {
    lastError_ = TicketEngineError::INVALID_CHALLENGE;
    return false;
  }
  if (epochGuard_.isReserved(challenge.epochNumber)) {
    if (allowCachedRetry && hasRetryCache_ &&
        challenge.epochNumber == cachedEpoch_ &&
        constantTimeEqual(challengeHash, cachedChallengeHash_,
                          sizeof(challengeHash)) &&
        output != nullptr && outputCapacity >= cachedSubmissionLength_) {
      memcpy(output, cachedSubmission_, cachedSubmissionLength_);
      outputLength = cachedSubmissionLength_;
      epochNumber = cachedEpoch_;
      lastError_ = TicketEngineError::NONE;
      return true;
    }
    lastError_ = TicketEngineError::EPOCH_ALREADY_RESERVED;
    return false;
  }
  if (!buildTicketSubmission(*identity_, canonicalChallenge, challengeLength,
                             output, outputCapacity, outputLength, ticket)) {
    outputLength = 0;
    lastError_ = TicketEngineError::BUILD_FAILED;
    return false;
  }
  if (outputLength > sizeof(cachedSubmission_)) {
    outputLength = 0;
    lastError_ = TicketEngineError::BUILD_FAILED;
    return false;
  }
  if (!epochGuard_.reserve(challenge.epochNumber)) {
    outputLength = 0;
    lastError_ = TicketEngineError::STATE_RESERVATION_FAILED;
    return false;
  }
  memcpy(cachedChallengeHash_, challengeHash, sizeof(challengeHash));
  memcpy(cachedSubmission_, output, outputLength);
  cachedSubmissionLength_ = outputLength;
  cachedEpoch_ = challenge.epochNumber;
  hasRetryCache_ = true;
  epochNumber = challenge.epochNumber;
  lastError_ = TicketEngineError::NONE;
  return true;
}

TicketEngineError EPDNTicketEngine::lastError() const { return lastError_; }

}  // namespace epdn
