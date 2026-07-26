#include "SerialFrame.h"

namespace epdn {
namespace {

constexpr uint8_t kMagic[] = {'E', 'P', 'G', '1'};

uint32_t crc32(const uint8_t *data, size_t length, uint32_t crc = 0xffffffffU) {
  for (size_t index = 0; index < length; ++index) {
    crc ^= data[index];
    for (uint8_t bit = 0; bit < 8; ++bit) {
      const uint32_t mask = 0U - (crc & 1U);
      crc = (crc >> 1) ^ (0xedb88320U & mask);
    }
  }
  return crc;
}

bool readExact(Stream &stream, uint8_t *output, size_t length,
               uint32_t deadline) {
  size_t offset = 0;
  while (offset < length) {
    if (stream.available() > 0) {
      const int value = stream.read();
      if (value >= 0) {
        output[offset++] = static_cast<uint8_t>(value);
      }
    } else {
      if (static_cast<int32_t>(millis() - deadline) >= 0) {
        return false;
      }
      yield();
    }
  }
  return true;
}

}  // namespace

bool readSerialFrame(Stream &stream, SerialFrame &frame, uint32_t timeoutMs) {
  if (timeoutMs == 0 || timeoutMs > 30000) {
    return false;
  }
  const uint32_t deadline = millis() + timeoutMs;
  uint8_t header[7] = {0};
  if (!readExact(stream, header, sizeof(header), deadline) ||
      memcmp(header, kMagic, sizeof(kMagic)) != 0) {
    return false;
  }
  const size_t length =
      (static_cast<size_t>(header[5]) << 8) | header[6];
  if (length > kMaxSerialFramePayload) {
    return false;
  }
  frame.type = static_cast<SerialFrameType>(header[4]);
  frame.length = length;
  uint8_t crcBytes[4] = {0};
  if (!readExact(stream, frame.payload, length, deadline) ||
      !readExact(stream, crcBytes, sizeof(crcBytes), deadline)) {
    return false;
  }
  const uint32_t expected =
      (static_cast<uint32_t>(crcBytes[0]) << 24) |
      (static_cast<uint32_t>(crcBytes[1]) << 16) |
      (static_cast<uint32_t>(crcBytes[2]) << 8) | crcBytes[3];
  uint32_t actual = crc32(header, sizeof(header));
  actual = crc32(frame.payload, length, actual) ^ 0xffffffffU;
  return actual == expected;
}

bool writeSerialFrame(Stream &stream, SerialFrameType type,
                      const uint8_t *payload, size_t payloadLength) {
  if ((payload == nullptr && payloadLength != 0) ||
      payloadLength > kMaxSerialFramePayload) {
    return false;
  }
  uint8_t header[7] = {
      kMagic[0],
      kMagic[1],
      kMagic[2],
      kMagic[3],
      static_cast<uint8_t>(type),
      static_cast<uint8_t>(payloadLength >> 8),
      static_cast<uint8_t>(payloadLength),
  };
  uint32_t crc = crc32(header, sizeof(header));
  crc = crc32(payload, payloadLength, crc) ^ 0xffffffffU;
  const uint8_t crcBytes[] = {
      static_cast<uint8_t>(crc >> 24), static_cast<uint8_t>(crc >> 16),
      static_cast<uint8_t>(crc >> 8), static_cast<uint8_t>(crc)};
  return stream.write(header, sizeof(header)) == sizeof(header) &&
         stream.write(payload, payloadLength) == payloadLength &&
         stream.write(crcBytes, sizeof(crcBytes)) == sizeof(crcBytes);
}

}  // namespace epdn
