#pragma once

#include <stddef.h>
#include <stdint.h>

#include "IdentityBackend.h"
#include "SecurityClass.h"

namespace epdn {

constexpr uint16_t kProtocolVersion = 1;
constexpr size_t kHashBytes = 32;
constexpr size_t kCompressedP256PublicKeyBytes = 33;
constexpr size_t kRawP256SignatureBytes = 64;
constexpr size_t kMaxChainIdBytes = 64;
constexpr size_t kMaxChallengeBytes = 512;
constexpr size_t kMaxSubmissionBytes = 8192;

struct EpochChallengeView {
  uint16_t protocolVersion;
  char chainId[kMaxChainIdBytes + 1];
  uint64_t epochNumber;
  uint8_t previousBlockHash[kHashBytes];
  uint8_t networkRandomness[kHashBytes];
  uint8_t devicePublicKeyHash[kHashBytes];
  uint8_t approvedFirmwareId[kHashBytes];
  SecurityClass securityClass;
};

// Strictly parses EPDN binary V1 object type 1. Oversized, truncated,
// non-canonical, unsupported-version, and trailing-byte inputs are rejected.
bool parseEpochChallenge(const uint8_t *input, size_t inputLength,
                         EpochChallengeView &output);

bool buildTicketSubmission(IdentityBackend &identity,
                           const uint8_t *canonicalChallenge,
                           size_t challengeLength, uint8_t *output,
                           size_t outputCapacity, size_t &outputLength,
                           uint8_t ticketOut[kHashBytes]);

bool hashDomain(const char *domain, const uint8_t *const *parts,
                const size_t *partLengths, size_t partCount,
                uint8_t output[kHashBytes]);

bool constantTimeEqual(const uint8_t *left, const uint8_t *right,
                       size_t length);

bool developmentFirmwareId(uint8_t output[kHashBytes]);

}  // namespace epdn
