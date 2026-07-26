#include <Arduino.h>
#include <EPDN.h>

// UART wire format is EPG1 | type:u8 | length:u16be | payload | crc32be.
// The gateway sends canonical node challenge bytes (type 1). The device alone
// creates proof/signature and returns the signed submission (type 2).
epdn::IdentityESP32Hardware identity;
epdn::EPDNTicketEngine ticketEngine;

#ifndef EPDN_NETWORK_ID
#define EPDN_NETWORK_ID "epdn-local-testnet-v1"
#endif

void sendError(uint8_t code) {
  epdn::writeSerialFrame(Serial, epdn::SerialFrameType::ERROR, &code, 1);
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(250);
  if (!ticketEngine.begin(identity, EPDN_NETWORK_ID, false)) {
    sendError(1);
  }
}

void loop() {
  if (Serial.available() <= 0) {
    yield();
    return;
  }
  epdn::SerialFrame frame{};
  if (!epdn::readSerialFrame(Serial, frame, 1000)) {
    sendError(2);
    return;
  }
  if (frame.type != epdn::SerialFrameType::CHALLENGE ||
      frame.length > epdn::kMaxChallengeBytes) {
    sendError(3);
    return;
  }

  uint8_t submission[1024] = {0};
  size_t submissionLength = 0;
  uint64_t epoch = 0;
  if (!ticketEngine.createSubmission(frame.payload, frame.length, submission,
                                     sizeof(submission), submissionLength,
                                     epoch, true)) {
    // Codes 21..28 map directly to TicketEngineError 1..8. No challenge,
    // identity, key, MAC, or other payload bytes are logged.
    sendError(20 + static_cast<uint8_t>(ticketEngine.lastError()));
    return;
  }
  epdn::writeSerialFrame(Serial, epdn::SerialFrameType::SUBMISSION, submission,
                         submissionLength);
}
