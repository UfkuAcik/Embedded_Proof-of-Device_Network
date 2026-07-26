#include <Arduino.h>
#include <EPDN.h>

epdn::IdentityATECC608 identity;

void setup() {
  Serial.begin(115200);
  delay(300);
  // No fallback is attempted. This backend remains unavailable until an
  // ATECC608 transport, slot policy, certificate chain, and signer are wired.
  if (!identity.begin()) {
    Serial.println(
        "{\"component\":\"epdn-miner\",\"level\":\"error\","
        "\"event\":\"atecc608_backend_unavailable\"}");
  }
}

void loop() { delay(1000); }
