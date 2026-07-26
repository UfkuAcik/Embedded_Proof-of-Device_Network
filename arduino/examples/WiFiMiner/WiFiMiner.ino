#include <Arduino.h>
#include <EPDN.h>
#include <Preferences.h>
#include <WiFi.h>
#include <mbedtls/platform_util.h>

#if __has_include("secrets_local.h")
#include "secrets_local.h"
#else
#define EPDN_WIFI_SSID ""
#define EPDN_WIFI_PASSWORD ""
#define EPDN_VALIDATOR_URL "http://192.168.1.2:8080"
#define EPDN_NETWORK_ID "epdn-local-testnet-v1"
#endif

epdn::IdentityESP32Hardware identity;
epdn::EPDNMiner miner;

bool loadProvisionedWifi(char ssid[33], char password[64]) {
  Preferences preferences;
  if (!preferences.begin("epdn_wifi", true)) {
    return false;
  }
  const size_t ssidLength = preferences.getBytesLength("ssid");
  const size_t passwordLength = preferences.getBytesLength("password");
  const bool valid = ssidLength > 0 && ssidLength <= 32 &&
                     passwordLength <= 63 &&
                     preferences.getBytes("ssid", ssid, ssidLength) ==
                         ssidLength &&
                     preferences.getBytes("password", password,
                                          passwordLength) == passwordLength;
  preferences.end();
  if (valid) {
    ssid[ssidLength] = '\0';
    password[passwordLength] = '\0';
  }
  return valid;
}

void setup() {
  Serial.begin(115200);
  delay(300);
  char ssid[33] = {0};
  char password[64] = {0};
  if (strlen(EPDN_WIFI_SSID) > 0) {
    strlcpy(ssid, EPDN_WIFI_SSID, sizeof(ssid));
    strlcpy(password, EPDN_WIFI_PASSWORD, sizeof(password));
  } else if (!loadProvisionedWifi(ssid, password)) {
    Serial.println(
        "{\"component\":\"epdn-miner\",\"level\":\"error\","
        "\"event\":\"wifi_not_provisioned\"}");
    return;
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  mbedtls_platform_zeroize(password, sizeof(password));

  epdn::EPDNConfig config;
  config.validatorUrl = EPDN_VALIDATOR_URL;
  config.networkId = EPDN_NETWORK_ID;
  config.identity = &identity;
  config.production = false;
  if (!miner.begin(config)) {
    Serial.println(
        "{\"component\":\"epdn-miner\",\"level\":\"error\","
        "\"event\":\"miner_init_failed\"}");
  }
}

void loop() { miner.process(); }
