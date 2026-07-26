#include "Protocol.h"

#include <string.h>

#include <mbedtls/sha256.h>

namespace epdn {
namespace {

constexpr uint8_t kMagic[] = {'E', 'P', 'D', 'N'};
constexpr uint8_t kEpochChallengeType = 1;
constexpr uint8_t kTicketSubmissionType = 4;

class Reader {
 public:
  Reader(const uint8_t *input, size_t length)
      : input_(input), length_(length), offset_(0) {}

  bool fixed(uint8_t *output, size_t count) {
    if (output == nullptr || count > length_ - offset_) {
      return false;
    }
    memcpy(output, input_ + offset_, count);
    offset_ += count;
    return true;
  }
  bool u8(uint8_t &value) { return fixed(&value, 1); }
  bool u16(uint16_t &value) {
    uint8_t bytes[2];
    if (!fixed(bytes, sizeof(bytes))) {
      return false;
    }
    value = (static_cast<uint16_t>(bytes[0]) << 8) | bytes[1];
    return true;
  }
  bool u64(uint64_t &value) {
    uint8_t bytes[8];
    if (!fixed(bytes, sizeof(bytes))) {
      return false;
    }
    value = 0;
    for (uint8_t byte : bytes) {
      value = (value << 8) | byte;
    }
    return true;
  }
  bool finished() const { return offset_ == length_; }

 private:
  const uint8_t *input_;
  size_t length_;
  size_t offset_;
};

class Writer {
 public:
  Writer(uint8_t *output, size_t capacity)
      : output_(output), capacity_(capacity), length_(0) {}
  bool fixed(const uint8_t *data, size_t count) {
    if (data == nullptr || count > capacity_ - length_) {
      return false;
    }
    memcpy(output_ + length_, data, count);
    length_ += count;
    return true;
  }
  bool u8(uint8_t value) { return fixed(&value, 1); }
  bool u16(uint16_t value) {
    const uint8_t bytes[] = {static_cast<uint8_t>(value >> 8),
                             static_cast<uint8_t>(value)};
    return fixed(bytes, sizeof(bytes));
  }
  bool u32(uint32_t value) {
    const uint8_t bytes[] = {
        static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
    return fixed(bytes, sizeof(bytes));
  }
  size_t length() const { return length_; }

 private:
  uint8_t *output_;
  size_t capacity_;
  size_t length_;
};

bool header(Writer &writer, uint8_t objectType) {
  return writer.fixed(kMagic, sizeof(kMagic)) && writer.u8(objectType) &&
         writer.u16(kProtocolVersion);
}

bool readHeader(Reader &reader, uint8_t expectedType) {
  uint8_t magic[sizeof(kMagic)] = {0};
  uint8_t actualType = 0;
  uint16_t version = 0;
  return reader.fixed(magic, sizeof(magic)) &&
         constantTimeEqual(magic, kMagic, sizeof(kMagic)) &&
         reader.u8(actualType) && actualType == expectedType &&
         reader.u16(version) && version == kProtocolVersion;
}

}  // namespace

bool parseEpochChallenge(const uint8_t *input, size_t inputLength,
                         EpochChallengeView &output) {
  if (input == nullptr || inputLength < 7 ||
      inputLength > kMaxChallengeBytes) {
    return false;
  }
  Reader reader(input, inputLength);
  uint16_t chainLength = 0;
  uint8_t securityClass = 0;
  if (!readHeader(reader, kEpochChallengeType) || !reader.u16(chainLength) ||
      chainLength > kMaxChainIdBytes ||
      !reader.fixed(reinterpret_cast<uint8_t *>(output.chainId), chainLength)) {
    return false;
  }
  output.chainId[chainLength] = '\0';
  if (!reader.u64(output.epochNumber) ||
      !reader.fixed(output.previousBlockHash, kHashBytes) ||
      !reader.fixed(output.networkRandomness, kHashBytes) ||
      !reader.fixed(output.devicePublicKeyHash, kHashBytes) ||
      !reader.fixed(output.approvedFirmwareId, kHashBytes) ||
      !reader.u8(securityClass) || securityClass > 4 || !reader.finished()) {
    return false;
  }
  output.protocolVersion = kProtocolVersion;
  output.securityClass = static_cast<SecurityClass>(securityClass);
  return true;
}

bool buildTicketSubmission(IdentityBackend &identity,
                           const uint8_t *canonicalChallenge,
                           size_t challengeLength, uint8_t *output,
                           size_t outputCapacity, size_t &outputLength,
                           uint8_t ticketOut[kHashBytes]) {
  outputLength = 0;
  if (canonicalChallenge == nullptr || challengeLength > kMaxChallengeBytes ||
      challengeLength == 0 || output == nullptr || ticketOut == nullptr ||
      outputCapacity > kMaxSubmissionBytes) {
    return false;
  }

  EpochChallengeView challenge{};
  if (!parseEpochChallenge(canonicalChallenge, challengeLength, challenge) ||
      challenge.securityClass != identity.securityClass()) {
    return false;
  }

  uint8_t publicKey[kCompressedP256PublicKeyBytes] = {0};
  size_t publicKeyLength = 0;
  if (!identity.getPublicKey(publicKey, sizeof(publicKey), publicKeyLength) ||
      publicKeyLength != sizeof(publicKey)) {
    return false;
  }
  const uint8_t *publicKeyParts[] = {publicKey};
  const size_t publicKeyPartLengths[] = {sizeof(publicKey)};
  uint8_t publicKeyHash[kHashBytes] = {0};
  if (!hashDomain("EPDN_DEVICE_PUBLIC_KEY_V1", publicKeyParts,
                  publicKeyPartLengths, 1, publicKeyHash) ||
      !constantTimeEqual(publicKeyHash, challenge.devicePublicKeyHash,
                         sizeof(publicKeyHash))) {
    return false;
  }

  uint8_t proof[kRawP256SignatureBytes] = {0};
  size_t proofLength = 0;
  if (!identity.createDeterministicProof(
          canonicalChallenge, challengeLength, proof, sizeof(proof),
          proofLength) ||
      proofLength != sizeof(proof)) {
    return false;
  }

  // Proof bytes prove possession but are not eligibility input. A verifier
  // cannot prove RFC6979 nonce use, so including ECDSA bytes would allow a
  // malicious provisioned signer to grind nonces for a better score.
  const uint8_t *ticketParts[] = {publicKeyHash, canonicalChallenge};
  const size_t ticketPartLengths[] = {sizeof(publicKeyHash), challengeLength};
  if (!hashDomain("EPDN_TICKET_V1", ticketParts, ticketPartLengths, 2,
                  ticketOut)) {
    return false;
  }

  const uint8_t *submissionParts[] = {canonicalChallenge, ticketOut};
  const size_t submissionPartLengths[] = {challengeLength, kHashBytes};
  uint8_t submissionHash[kHashBytes] = {0};
  if (!hashDomain("EPDN_SUBMISSION_V1", submissionParts,
                  submissionPartLengths, 2, submissionHash)) {
    return false;
  }
  uint8_t signature[kRawP256SignatureBytes] = {0};
  size_t signatureLength = 0;
  if (!identity.sign(submissionHash, sizeof(submissionHash), signature,
                     sizeof(signature), signatureLength) ||
      signatureLength != sizeof(signature)) {
    return false;
  }

  Writer writer(output, outputCapacity);
  if (challengeLength > UINT32_MAX ||
      !header(writer, kTicketSubmissionType) ||
      !writer.u32(static_cast<uint32_t>(challengeLength)) ||
      !writer.fixed(canonicalChallenge, challengeLength) ||
      !writer.u16(sizeof(proof)) || !writer.fixed(proof, sizeof(proof)) ||
      !writer.fixed(ticketOut, kHashBytes) ||
      !writer.u16(sizeof(signature)) ||
      !writer.fixed(signature, sizeof(signature))) {
    return false;
  }
  outputLength = writer.length();
  return outputLength <= kMaxSubmissionBytes;
}

bool hashDomain(const char *domain, const uint8_t *const *parts,
                const size_t *partLengths, size_t partCount,
                uint8_t output[kHashBytes]) {
  if (domain == nullptr || parts == nullptr || partLengths == nullptr ||
      output == nullptr || partCount > 8) {
    return false;
  }
  mbedtls_sha256_context context;
  mbedtls_sha256_init(&context);
  bool ok = mbedtls_sha256_starts_ret(&context, 0) == 0 &&
            mbedtls_sha256_update_ret(
                &context, reinterpret_cast<const uint8_t *>(domain),
                strlen(domain)) == 0;
  for (size_t index = 0; ok && index < partCount; ++index) {
    if (parts[index] == nullptr) {
      ok = false;
      break;
    }
    ok = mbedtls_sha256_update_ret(&context, parts[index],
                                   partLengths[index]) == 0;
  }
  ok = ok && mbedtls_sha256_finish_ret(&context, output) == 0;
  mbedtls_sha256_free(&context);
  return ok;
}

bool constantTimeEqual(const uint8_t *left, const uint8_t *right,
                       size_t length) {
  if (left == nullptr || right == nullptr) {
    return false;
  }
  uint8_t difference = 0;
  for (size_t index = 0; index < length; ++index) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool developmentFirmwareId(uint8_t output[kHashBytes]) {
  static const uint8_t label[] = "epdn-miner-development";
  const uint8_t *parts[] = {label};
  const size_t lengths[] = {sizeof(label) - 1};
  return hashDomain("EPDN_FIRMWARE_ID_V1", parts, lengths, 1, output);
}

}  // namespace epdn
