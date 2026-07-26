#pragma once

#include <Arduino.h>

namespace epdn {

constexpr size_t kMaxSerialFramePayload = 2048;

enum class SerialFrameType : uint8_t {
  CHALLENGE = 1,
  SUBMISSION = 2,
  PROVISIONING_HELLO = 16,
  WIFI_CREDENTIALS = 17,
  DEVICE_CERTIFICATE = 18,
  ENROLL_DEV = 19,
  ACK = 126,
  ERROR = 127,
};

struct SerialFrame {
  SerialFrameType type;
  size_t length;
  uint8_t payload[kMaxSerialFramePayload];
};

bool readSerialFrame(Stream &stream, SerialFrame &frame, uint32_t timeoutMs);
bool writeSerialFrame(Stream &stream, SerialFrameType type,
                      const uint8_t *payload, size_t payloadLength);

}  // namespace epdn
