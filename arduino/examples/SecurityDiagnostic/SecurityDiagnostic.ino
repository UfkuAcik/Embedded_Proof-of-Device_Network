#include <Arduino.h>
#include <EPDN.h>

#include <esp_flash_encrypt.h>
#include <esp_secure_boot.h>
#include <esp_system.h>

void setup() {
  Serial.begin(115200);
  delay(300);

  Serial.println("{\"component\":\"epdn-diagnostic\",\"event\":\"start\"}");
  Serial.printf(
      "{\"chip_model\":\"%s\",\"chip_revision\":%u,"
      "\"cpu_mhz\":%u,\"flash_bytes\":%u}\n",
      ESP.getChipModel(), ESP.getChipRevision(), ESP.getCpuFreqMHz(),
      ESP.getFlashChipSize());
  Serial.printf(
      "{\"heap_total\":%u,\"heap_free\":%u,\"heap_min_free\":%u,"
      "\"reset_reason\":%d}\n",
      ESP.getHeapSize(), ESP.getFreeHeap(), ESP.getMinFreeHeap(),
      static_cast<int>(esp_reset_reason()));
  Serial.printf(
      "{\"secure_boot_enabled\":%s,\"flash_encryption_enabled\":%s}\n",
      esp_secure_boot_enabled() ? "true" : "false",
      esp_flash_encryption_enabled() ? "true" : "false");

  Serial.printf(
      "{\"identity_initialized\":false,\"candidate_security_class\":\"%s\","
      "\"attestation_supported\":false,"
      "\"note\":\"read-only capability report; no identity or NVS write; "
      "MAC and secrets omitted\"}\n",
      epdn::securityClassName(epdn::SecurityClass::L0_SOFTWARE_TEST));
}

void loop() { delay(1000); }
