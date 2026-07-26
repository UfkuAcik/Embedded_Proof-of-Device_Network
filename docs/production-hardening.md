# Production hardening plan

EPDN MVP is not production-ready. Before any production network:

1. Freeze and independently review the deterministic encoding, state machine,
   domain separation, certificate profile, and consensus upgrade rules.
2. Move issuance under offline root and HSM-backed intermediate authorities
   with dual control, inventory reconciliation, and public audit artifacts.
3. Qualify each chip/board/security-backend tuple independently. Never promote
   compile-only support to hardware-tested.
4. Enable secure boot, flash encryption, anti-rollback, and debug restrictions
   only through chip-specific reviewed ceremonies with recovery planning.
5. Require reproducible signed firmware, staged OTA, health rollback, and
   measured/attested firmware policies.
6. Replace local-testnet peer logic with a reviewed Byzantine finality protocol
   and slashing/evidence rules for randomness withholding and equivocation.
7. Run continuous parser and state-machine fuzzing, dependency scanning, secret
   scanning, penetration testing, browser CSP review, and supply-chain controls.
8. Define incident response, certificate renewal, revocation propagation,
   validator key rotation, disaster recovery, and data-retention policies.

The design must never claim mathematical emulator detection across all supported
platforms. It can only state the assurance provided by a specific, verified
non-exportable identity and attestation chain.
