#include <Arduino.h>
#include <EPDN.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

namespace {

constexpr char kChallengeHex[] =
    "4550444e01000100136570646e2d766563746f722d746573746e657400000000"
    "0000002a11111111111111111111111111111111111111111111111111111111"
    "1111111122222222222222222222222222222222222222222222222222222222"
    "22222222daebf1366b5fd6c6959e59bda681c0770e6bef06aadfd7824bb33520"
    "86e26aab9c835a7fefdaf7d46dd72b0a93855a656d2b1f4240e34921cd054828"
    "65ab722702";
constexpr char kPublicKeyHex[] =
    "02550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e"
    "24";
constexpr char kProofHex[] =
    "d847041eb7d96c00b4ecd335feab52580fb51c08be237bbc2a775df441935418"
    "ee236a97a4bb8230cd82f4045fadef7682f6ad11eeae06a8f2e8af9b6c6cb940";
constexpr char kSignatureHex[] =
    "cc2bf64cbb96acdfbc6166e6bfcd9b58e4b2596af7d6f6bb6e735e400e5d6eb9"
    "085241a5eab1c36d15e8906462624005c892c64a59778715642d30265d9b7ebd";
constexpr char kTicketHex[] =
    "9c573d056cb84a9bd6aff8e6d2119daaa43ebb74fb42398f8c047602fb0e603c";
constexpr char kSubmissionHex[] =
    "4550444e040001000000a54550444e01000100136570646e2d766563746f722d"
    "746573746e6574000000000000002a1111111111111111111111111111111111"
    "1111111111111111111111111111112222222222222222222222222222222222"
    "222222222222222222222222222222daebf1366b5fd6c6959e59bda681c0770e"
    "6bef06aadfd7824bb3352086e26aab9c835a7fefdaf7d46dd72b0a93855a656d"
    "2b1f4240e34921cd05482865ab7227020040d847041eb7d96c00b4ecd335feab"
    "52580fb51c08be237bbc2a775df441935418ee236a97a4bb8230cd82f4045fad"
    "ef7682f6ad11eeae06a8f2e8af9b6c6cb9409c573d056cb84a9bd6aff8e6d211"
    "9daaa43ebb74fb42398f8c047602fb0e603c0040cc2bf64cbb96acdfbc6166e6"
    "bfcd9b58e4b2596af7d6f6bb6e735e400e5d6eb9085241a5eab1c36d15e89064"
    "62624005c892c64a59778715642d30265d9b7ebd";

int nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

bool decodeHex(const char *input, uint8_t *output, size_t capacity,
               size_t &length) {
  length = 0;
  const size_t characters = strlen(input);
  if ((characters & 1U) != 0 || characters / 2 > capacity) return false;
  for (size_t index = 0; index < characters; index += 2) {
    const int high = nibble(input[index]);
    const int low = nibble(input[index + 1]);
    if (high < 0 || low < 0) return false;
    output[length++] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

// Uses the public test fixture scalar 0x02...02. This is not a production key.
// mbedTLS performs RFC6979 P-256 signing so the vector verifies the signer as
// well as the encoder/hash path.
class VectorIdentity final : public epdn::IdentityBackend {
 public:
  VectorIdentity() : ready_(false) { mbedtls_ecp_keypair_init(&key_); }
  ~VectorIdentity() override { mbedtls_ecp_keypair_free(&key_); }
  bool begin() override {
    uint8_t privateScalar[32];
    memset(privateScalar, 2, sizeof(privateScalar));
    ready_ =
        mbedtls_ecp_group_load(&key_.grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_mpi_read_binary(&key_.d, privateScalar,
                                sizeof(privateScalar)) == 0 &&
        mbedtls_ecp_check_privkey(&key_.grp, &key_.d) == 0;
    mbedtls_platform_zeroize(privateScalar, sizeof(privateScalar));
    return ready_;
  }
  epdn::SecurityClass securityClass() const override {
    return epdn::SecurityClass::L2_NATIVE_HARDWARE_IDENTITY;
  }
  bool getDeviceId(uint8_t *, size_t, size_t &length) override {
    length = 0;
    return false;
  }
  bool getPublicKey(uint8_t *output, size_t capacity,
                    size_t &length) override {
    return decodeHex(kPublicKeyHex, output, capacity, length);
  }
  bool createDeterministicProof(const uint8_t *challenge, size_t challengeLength,
                                uint8_t *output, size_t capacity,
                                size_t &length) override {
    const uint8_t *parts[] = {challenge};
    const size_t lengths[] = {challengeLength};
    uint8_t digest[epdn::kHashBytes] = {0};
    const bool ok =
        epdn::hashDomain("EPDN_PROOF_V1", parts, lengths, 1, digest) &&
        signDigest(digest, output, capacity, length);
    mbedtls_platform_zeroize(digest, sizeof(digest));
    return ok;
  }
  bool sign(const uint8_t *message, size_t messageLength, uint8_t *output,
            size_t capacity,
            size_t &length) override {
    if (messageLength != epdn::kHashBytes) return false;
    return signDigest(message, output, capacity, length);
  }
  bool getAttestation(const uint8_t *, size_t, uint8_t *, size_t,
                      size_t &length) override {
    length = 0;
    return false;
  }

 private:
  bool signDigest(const uint8_t digest[32], uint8_t *output, size_t capacity,
                  size_t &length) {
    length = 0;
    if (!ready_ || output == nullptr ||
        capacity < epdn::kRawP256SignatureBytes) {
      return false;
    }
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    bool ok = mbedtls_ecdsa_sign_det(&key_.grp, &r, &s, &key_.d, digest, 32,
                                     MBEDTLS_MD_SHA256) == 0;
    if (ok) {
      ok = mbedtls_mpi_write_binary(&r, output, 32) == 0 &&
           mbedtls_mpi_write_binary(&s, output + 32, 32) == 0;
    }
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    if (ok) length = epdn::kRawP256SignatureBytes;
    return ok;
  }

  bool ready_;
  mbedtls_ecp_keypair key_;
};

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(200);

  uint8_t challenge[epdn::kMaxChallengeBytes] = {0};
  uint8_t expectedTicket[epdn::kHashBytes] = {0};
  uint8_t expectedSubmission[1024] = {0};
  size_t challengeLength = 0;
  size_t expectedTicketLength = 0;
  size_t expectedSubmissionLength = 0;
  const bool decodeOk =
      decodeHex(kChallengeHex, challenge, sizeof(challenge),
                challengeLength) &&
      decodeHex(kTicketHex, expectedTicket, sizeof(expectedTicket),
                expectedTicketLength) &&
      decodeHex(kSubmissionHex, expectedSubmission,
                sizeof(expectedSubmission), expectedSubmissionLength);

  VectorIdentity identity;
  uint8_t actualTicket[epdn::kHashBytes] = {0};
  uint8_t actualSubmission[1024] = {0};
  size_t actualSubmissionLength = 0;
  const bool identityOk = identity.begin();
  const bool buildOk =
      decodeOk && identityOk &&
      epdn::buildTicketSubmission(
          identity, challenge, challengeLength, actualSubmission,
          sizeof(actualSubmission), actualSubmissionLength, actualTicket);
  const bool ticketMatch =
      buildOk && expectedTicketLength == sizeof(actualTicket) &&
      epdn::constantTimeEqual(expectedTicket, actualTicket,
                              sizeof(actualTicket));
  const bool submissionLengthMatch =
      buildOk && expectedSubmissionLength == actualSubmissionLength;
  const bool submissionMatch =
      submissionLengthMatch &&
      epdn::constantTimeEqual(expectedSubmission, actualSubmission,
                              actualSubmissionLength);
  const bool ok = decodeOk && identityOk && buildOk && ticketMatch &&
                  submissionLengthMatch && submissionMatch;

  Serial.printf(
      "{\"component\":\"epdn-protocol-vector\",\"vector\":\"v1\","
      "\"decode\":%s,\"identity_begin\":%s,\"build\":%s,"
      "\"ticket_match\":%s,\"submission_length_match\":%s,"
      "\"submission_match\":%s,\"result\":\"%s\"}\n",
      decodeOk ? "true" : "false", identityOk ? "true" : "false",
      buildOk ? "true" : "false", ticketMatch ? "true" : "false",
      submissionLengthMatch ? "true" : "false",
      submissionMatch ? "true" : "false", ok ? "PASS" : "FAIL");
}

void loop() { delay(1000); }
