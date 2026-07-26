# Provisioning

Development enrollment and production provisioning are intentionally separate.

## Development enrollment

1. Inspect the explicitly selected port and chip without changing eFuses.
2. Generate a disposable development identity.
3. Issue a short-lived certificate from the local development CA.
4. Store the certificate and development identity in the device's designated
   storage.
5. Register the certificate and firmware policy with the local validator.
6. Upload the miner firmware, monitor redacted logs, and verify first-ticket,
   duplicate, and revocation behavior.

Development software keys do not prove physical uniqueness.

## Production security plan

The production command is a dry-run planner by default. A credible ceremony
requires an offline root CA, HSM-backed intermediate, operator role separation,
dual control, tamper-evident audit records, per-batch inventory, certificate
expiry/renewal, emergency denylisting, signed reproducible firmware, verified
Secure Boot/Flash Encryption policy, anti-rollback, and debug-interface policy.

No irreversible change is allowed unless the exact command contains
`--confirm-irreversible-security-changes`. Even then, the tool must first print
every target field, current value, proposed value, consequence, recovery status,
and chip-specific source of truth. The MVP never runs that path automatically.
