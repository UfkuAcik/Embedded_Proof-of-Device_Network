# Security classes and capability rules

```cpp
enum class SecurityClass {
    L0_SOFTWARE_TEST,
    L1_PROTECTED_SOFTWARE_IDENTITY,
    L2_NATIVE_HARDWARE_IDENTITY,
    L3_EXTERNAL_SECURE_ELEMENT,
    L4_ATTESTED_PLATFORM
};
```

## No silent downgrade

A requested backend must either initialize with all required capabilities or
return a structured failure. A board macro is not evidence that secure boot,
flash encryption, key isolation, or attestation is configured.

| Class | Private-key exposure | Network policy | Minimum evidence |
|---|---|---|---|
| L0 | Exportable software key | development only | explicit insecure build flag |
| L1 | May be readable by firmware | testnet; production only by explicit policy | protected storage and boot configuration report |
| L2 | Signing/derivation operation is hardware-bound | eligible when model and configuration are verified | capability probe plus provisioning record |
| L3 | Key never leaves secure element | eligible when device and certificate slot are verified | secure-element identity and signed operation test |
| L4 | Platform emits signed measurements | strongest policy tier | verified attestation chain and freshness nonce |

The initially detected ESP32 chip is **not** assigned L2 or L4 merely because it
is an ESP32. Its exact security configuration must first be measured.

## Compile-time capability detection

Architecture macros choose candidate adapters. Backend-specific feature macros
and runtime probes then prove the requested capability. Unknown combinations
fail compilation for production builds and may opt into L0 only for development.
