#include "EPDNMiner.h"

#if defined(ARDUINO_ARCH_ESP32)
#include <HTTPClient.h>
#include <WiFi.h>
#endif

namespace epdn {
namespace {

constexpr uint32_t kMinimumRetryMs = 1000;
constexpr uint32_t kMaximumRetryMs = 60000;
constexpr int kMaximumSubmissionResponseBytes = 4096;

char hexDigit(uint8_t value) {
  return value < 10 ? static_cast<char>('0' + value)
                    : static_cast<char>('a' + value - 10);
}

String hexLower(const uint8_t *bytes, size_t length) {
  String output;
  output.reserve(length * 2);
  for (size_t index = 0; index < length; ++index) {
    output += hexDigit(bytes[index] >> 4);
    output += hexDigit(bytes[index] & 0x0f);
  }
  return output;
}

int hexValue(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

bool isDue(uint32_t now, uint32_t deadline) {
  return static_cast<int32_t>(now - deadline) >= 0;
}

bool responseHasErrorCode(const String &body, const char *code) {
  String marker("\"error\":\"");
  marker += code;
  marker += "\"";
  return body.indexOf(marker) >= 0;
}

bool isDuplicateSubmissionResponse(const String &body) {
  return responseHasErrorCode(body, "duplicate_device_epoch") ||
         responseHasErrorCode(body, "duplicate_ticket") ||
         responseHasErrorCode(body, "duplicate_submission");
}

}  // namespace

EPDNMiner::EPDNMiner()
    : initialized_(false),
      nextActionAt_(0),
      retryDelayMs_(kMinimumRetryMs),
      pendingLength_(0),
      pendingEpoch_(0) {}

bool EPDNMiner::begin(const EPDNConfig &config) {
  if (config.validatorUrl == nullptr || config.networkId == nullptr ||
      config.identity == nullptr || strlen(config.validatorUrl) == 0 ||
      strlen(config.validatorUrl) > 192 || strlen(config.networkId) == 0 ||
      strlen(config.networkId) > kMaxChainIdBytes ||
      config.requestTimeoutMs < 250 || config.requestTimeoutMs > 30000) {
    logEvent("error", "configuration_rejected");
    return false;
  }
  if (config.production &&
      (strncmp(config.validatorUrl, "https://", 8) != 0 ||
       config.identity->securityClass() ==
           SecurityClass::L0_SOFTWARE_TEST)) {
    logEvent("error", "production_security_rejected");
    return false;
  }
  config_ = config;
  if (!ticketEngine_.begin(*config_.identity, config_.networkId,
                           config_.production)) {
    logEvent("error", "identity_or_state_init_failed");
    return false;
  }
  initialized_ = true;
  nextActionAt_ = millis();
  logEvent("info", "miner_ready",
           securityClassName(config_.identity->securityClass()));
  return true;
}

void EPDNMiner::process() {
  if (!initialized_) {
    yield();
    return;
  }
  const uint32_t now = millis();
  if (!isDue(now, nextActionAt_)) {
    yield();
    return;
  }
#if !defined(ARDUINO_ARCH_ESP32)
  scheduleRetry();
  return;
#else
  if (WiFi.status() != WL_CONNECTED) {
    logEvent("warn", "wifi_disconnected");
    WiFi.reconnect();
    scheduleRetry();
    yield();
    return;
  }
  if (pendingLength_ != 0) {
    const SubmissionResult result = submitPending();
    if (result == SubmissionResult::TRANSIENT_FAILURE) {
      logEvent("warn", "ticket_retry_scheduled");
      scheduleRetry();
    } else {
      pendingLength_ = 0;
      retryDelayMs_ = kMinimumRetryMs;
      nextActionAt_ = millis() + 1000;
      if (result == SubmissionResult::ACCEPTED) {
        logEvent("info", "ticket_accepted");
      } else if (result == SubmissionResult::ALREADY_RECORDED) {
        // Treat a duplicate as the acknowledgement for a possibly lost 2xx
        // response. The immutable per-epoch bytes must not remain wedged.
        logEvent("info", "ticket_already_recorded");
      } else {
        logEvent("warn", "ticket_permanently_rejected");
      }
    }
    yield();
    return;
  }

  uint8_t challengeBytes[kMaxChallengeBytes] = {0};
  size_t challengeLength = 0;
  EpochChallengeView challenge{};
  if (!fetchChallenge(challengeBytes, sizeof(challengeBytes),
                      challengeLength) ||
      !parseEpochChallenge(challengeBytes, challengeLength, challenge) ||
      strcmp(challenge.chainId, config_.networkId) != 0 ||
      challenge.securityClass != config_.identity->securityClass()) {
    logEvent("warn", "challenge_rejected");
    scheduleRetry();
    yield();
    return;
  }
  if (!ticketEngine_.createSubmission(
          challengeBytes, challengeLength, pendingSubmission_,
          sizeof(pendingSubmission_), pendingLength_, pendingEpoch_)) {
    pendingLength_ = 0;
    logEvent("error", "ticket_creation_failed");
    scheduleRetry();
    yield();
    return;
  }
  const SubmissionResult result = submitPending();
  if (result == SubmissionResult::TRANSIENT_FAILURE) {
    logEvent("warn", "ticket_retry_scheduled");
    scheduleRetry();
  } else {
    pendingLength_ = 0;
    retryDelayMs_ = kMinimumRetryMs;
    nextActionAt_ = millis() + 1000;
    if (result == SubmissionResult::ACCEPTED) {
      logEvent("info", "ticket_accepted");
    } else if (result == SubmissionResult::ALREADY_RECORDED) {
      logEvent("info", "ticket_already_recorded");
    } else {
      logEvent("warn", "ticket_permanently_rejected");
    }
  }
  yield();
#endif
}

bool EPDNMiner::fetchChallenge(uint8_t *output, size_t capacity,
                               size_t &length) {
  length = 0;
#if !defined(ARDUINO_ARCH_ESP32)
  (void)output;
  (void)capacity;
  return false;
#else
  String url(config_.validatorUrl);
  uint8_t deviceId[kHashBytes] = {0};
  size_t deviceIdLength = 0;
  uint8_t firmwareId[kHashBytes] = {0};
  if (!config_.identity->getDeviceId(deviceId, sizeof(deviceId),
                                     deviceIdLength) ||
      deviceIdLength != sizeof(deviceId) ||
      !developmentFirmwareId(firmwareId)) {
    return false;
  }
  url += "/api/v1/epochs/current/";
  url += hexLower(deviceId, sizeof(deviceId));
  url += "/";
  url += hexLower(firmwareId, sizeof(firmwareId));
  HTTPClient request;
  request.setTimeout(config_.requestTimeoutMs);
  if (!request.begin(url)) {
    return false;
  }
  request.addHeader("Accept", "application/json");
  const int status = request.GET();
  const int contentLength = request.getSize();
  bool ok = status == HTTP_CODE_OK && contentLength > 0 &&
            contentLength <= 1536;
  if (ok) {
    const String body = request.getString();
    const String marker = "\"challenge_hex\":\"";
    const int start = body.indexOf(marker);
    if (start < 0) {
      ok = false;
    } else {
      const int hexStart = start + marker.length();
      const int hexEnd = body.indexOf('"', hexStart);
      const int hexLength = hexEnd - hexStart;
      ok = hexEnd > hexStart && (hexLength % 2) == 0 &&
           static_cast<size_t>(hexLength / 2) <= capacity;
      for (int index = 0; ok && index < hexLength; index += 2) {
        const int high = hexValue(body[hexStart + index]);
        const int low = hexValue(body[hexStart + index + 1]);
        ok = high >= 0 && low >= 0;
        if (ok) {
          output[length++] = static_cast<uint8_t>((high << 4) | low);
        }
      }
    }
  }
  request.end();
  return ok;
#endif
}

SubmissionResult EPDNMiner::submitPending() {
#if !defined(ARDUINO_ARCH_ESP32)
  return SubmissionResult::TRANSIENT_FAILURE;
#else
  if (pendingLength_ == 0 || pendingLength_ > sizeof(pendingSubmission_)) {
    return SubmissionResult::PERMANENTLY_REJECTED;
  }
  String url(config_.validatorUrl);
  url += "/api/v1/tickets";
  HTTPClient request;
  request.setTimeout(config_.requestTimeoutMs);
  if (!request.begin(url)) {
    return SubmissionResult::TRANSIENT_FAILURE;
  }
  request.addHeader("Content-Type",
                    "application/vnd.epdn.v1+octet-stream");
  const int status =
      request.POST(pendingSubmission_, static_cast<int>(pendingLength_));
  const int contentLength = request.getSize();
  String body;
  if (status >= 400 && contentLength >= 0 &&
      contentLength <= kMaximumSubmissionResponseBytes) {
    body = request.getString();
  }
  request.end();
  if (status >= 200 && status < 300) {
    return SubmissionResult::ACCEPTED;
  }
  if (isDuplicateSubmissionResponse(body)) {
    return SubmissionResult::ALREADY_RECORDED;
  }
  if (status <= 0 || status >= 500 || status == 408 || status == 425 ||
      status == 429 || responseHasErrorCode(body, "future_epoch")) {
    return SubmissionResult::TRANSIENT_FAILURE;
  }
  if (status == 409 && body.length() == 0) {
    // A 409 without the bounded node error contract is ambiguous: it could be
    // a future epoch or a duplicate after a lost response. Preserve the bytes.
    return SubmissionResult::TRANSIENT_FAILURE;
  }
  // The signed bytes are immutable, so stale, malformed, wrong-chain,
  // revoked/paused/unregistered, and other bounded 4xx results cannot become
  // valid through retries.
  return SubmissionResult::PERMANENTLY_REJECTED;
#endif
}

void EPDNMiner::scheduleRetry() {
  nextActionAt_ = millis() + retryDelayMs_;
  if (retryDelayMs_ < kMaximumRetryMs) {
    retryDelayMs_ =
        min<uint32_t>(retryDelayMs_ * 2, kMaximumRetryMs);
  }
}

void EPDNMiner::logEvent(const char *level, const char *event,
                         const char *detail) const {
  Serial.print("{\"component\":\"epdn-miner\",\"level\":\"");
  Serial.print(level == nullptr ? "error" : level);
  Serial.print("\",\"event\":\"");
  Serial.print(event == nullptr ? "invalid" : event);
  if (detail != nullptr) {
    Serial.print("\",\"detail\":\"");
    Serial.print(detail);
  }
  Serial.println("\"}");
}

}  // namespace epdn
