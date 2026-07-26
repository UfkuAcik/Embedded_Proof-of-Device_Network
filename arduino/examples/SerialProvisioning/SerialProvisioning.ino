#include <Arduino.h>
#include <EPDN.h>
#include <Preferences.h>
#include <esp_flash_encrypt.h>
#include <mbedtls/platform_util.h>

#if defined(EPDN_PRODUCTION_BUILD) && \
    defined(EPDN_ALLOW_INSECURE_PLAINTEXT_WIFI_NVS)
#error "Plaintext Wi-Fi NVS opt-in is forbidden in production builds"
#endif

namespace {

constexpr size_t kMaxSsidBytes = 32;
constexpr size_t kMaxPasswordBytes = 63;
epdn::IdentityESP32Hardware developmentIdentity;

enum class WifiStoreResult : uint8_t {
  STORED = 0,
  INVALID_FRAME = 1,
  INSECURE_STORAGE_DISABLED = 2,
  STORAGE_FAILED = 3,
};

void acknowledge(uint8_t code) {
  epdn::writeSerialFrame(Serial, epdn::SerialFrameType::ACK, &code, 1);
}

void reject(uint8_t code) {
  epdn::writeSerialFrame(Serial, epdn::SerialFrameType::ERROR, &code, 1);
}

bool wifiCredentialStorageAllowed() {
  if (esp_flash_encryption_enabled()) {
    return true;
  }
#if defined(EPDN_ALLOW_INSECURE_PLAINTEXT_WIFI_NVS)
  // Development-only escape hatch. Production builds reject this macro above.
  return true;
#else
  return false;
#endif
}

WifiStoreResult storeWifiCredentials(const uint8_t *payload, size_t length) {
  if (payload == nullptr || length < 2) {
    return WifiStoreResult::INVALID_FRAME;
  }
  const size_t ssidLength = payload[0];
  const size_t passwordLength = payload[1];
  if (ssidLength == 0 || ssidLength > kMaxSsidBytes ||
      passwordLength > kMaxPasswordBytes ||
      length != 2 + ssidLength + passwordLength) {
    return WifiStoreResult::INVALID_FRAME;
  }
  if (!wifiCredentialStorageAllowed()) {
    return WifiStoreResult::INSECURE_STORAGE_DISABLED;
  }
  Preferences preferences;
  if (!preferences.begin("epdn_wifi", false)) {
    return WifiStoreResult::STORAGE_FAILED;
  }
  const bool ok =
      preferences.putBytes("ssid", payload + 2, ssidLength) == ssidLength &&
      preferences.putBytes("password", payload + 2 + ssidLength,
                           passwordLength) == passwordLength;
  preferences.end();
  return ok ? WifiStoreResult::STORED : WifiStoreResult::STORAGE_FAILED;
}

bool storeCertificateIfChanged(const uint8_t *certificate, size_t length) {
  if (certificate == nullptr || length == 0 ||
      length > epdn::kMaxSerialFramePayload || length < 7 ||
      memcmp(certificate, "EPDN\x03\x00\x01", 7) != 0) {
    return false;
  }
  Preferences preferences;
  if (!preferences.begin("epdn_cert", false)) {
    return false;
  }
  bool unchanged = preferences.getBytesLength("device_cert") == length;
  if (unchanged) {
    uint8_t existing[epdn::kMaxSerialFramePayload] = {0};
    unchanged =
        preferences.getBytes("device_cert", existing, length) == length &&
        epdn::constantTimeEqual(existing, certificate, length);
  }
  const bool ok =
      unchanged ||
      preferences.putBytes("device_cert", certificate, length) == length;
  preferences.end();
  return ok;
}

}  // namespace

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(250);
}

void loop() {
  if (Serial.available() <= 0) {
    yield();
    return;
  }
  epdn::SerialFrame frame{};
  if (!epdn::readSerialFrame(Serial, frame, 1000)) {
    reject(1);
    return;
  }
  if (frame.type == epdn::SerialFrameType::PROVISIONING_HELLO) {
    const uint8_t capabilities[] = {
        1,  // protocol version
        static_cast<uint8_t>(epdn::SecurityClass::L0_SOFTWARE_TEST),
        wifiCredentialStorageAllowed() ? static_cast<uint8_t>(1)
                                       : static_cast<uint8_t>(0),
    };
    epdn::writeSerialFrame(Serial, epdn::SerialFrameType::ACK, capabilities,
                           sizeof(capabilities));
    return;
  }
  if (frame.type == epdn::SerialFrameType::ENROLL_DEV) {
    if (frame.length != 0 || !developmentIdentity.begin()) {
      reject(4);
      return;
    }
    uint8_t publicKey[epdn::kCompressedP256PublicKeyBytes] = {0};
    size_t publicKeyLength = 0;
    if (!developmentIdentity.getPublicKey(publicKey, sizeof(publicKey),
                                          publicKeyLength)) {
      reject(5);
      return;
    }
    epdn::writeSerialFrame(Serial, epdn::SerialFrameType::ACK, publicKey,
                           publicKeyLength);
    return;
  }
  if (frame.type == epdn::SerialFrameType::WIFI_CREDENTIALS) {
    const WifiStoreResult result =
        storeWifiCredentials(frame.payload, frame.length);
    mbedtls_platform_zeroize(frame.payload, sizeof(frame.payload));
    if (result == WifiStoreResult::STORED) {
      acknowledge(0);
    } else if (result == WifiStoreResult::INSECURE_STORAGE_DISABLED) {
      reject(7);
    } else if (result == WifiStoreResult::STORAGE_FAILED) {
      reject(8);
    } else {
      reject(2);
    }
    return;
  }
  if (frame.type == epdn::SerialFrameType::DEVICE_CERTIFICATE) {
    if (storeCertificateIfChanged(frame.payload, frame.length)) {
      acknowledge(0);
    } else {
      reject(6);
    }
    return;
  }
  reject(3);
}
