# Recovery-key escrow

The optional recovery-escrow server module depends on desktop-policies and requires bitlocker.escrow in the scope ceiling. It retains TIBCON Sentry's upload, metadata and audited reveal workflows while storing only encrypted recovery material. The provider integration and production acceptance remain unfinished.

## Configuration

RECOVERY_ESCROW_KEYRING_FILE names an explicitly provisioned JSON document with activeKeyId and a keys map from key IDs to absolute filenames. Each referenced file contains exactly 32 binary bytes. CREDENTIAL_ROOT must name the protected absolute credential directory; referenced key files must resolve inside it. The [example](../deploy/alpha/recovery-keyring.example.json) contains placeholders only. Nothing generates keys or changes access on startup.

New records use the active key ID. Keep older encryption keys in the keyring to reveal older records; changing the active ID does not reencrypt history. Persist and protect those keys separately from database backups. Key provisioning, rotation and ACL verification must follow the credential-store instructions. No actual encryption key or endpoint recovery password was created while implementing this module.

## Upload and storage

POST /v1/agent/native-recovery-key takes policyDigest, volume, protectorId and recoveryKey. Device, enrollment and management scope derive from the exact authenticated native credential. Admission requires current signed module selection, selected BitLocker feature, escrow permission, enabled server module and recovery backup enabled in the effective desktop policy/canary.

Migration v9 adds recovery_key_escrow and the separate reveal grant. Each record uses AES-256-GCM with a fresh 96-bit nonce and authenticated binding to record ID, scope, device, enrollment, volume and protector. The recovery password is never persisted in plaintext. A retry for the same enrollment/protector verifies the existing encrypted record and returns its ID; different material conflicts instead of silently replacing a recovery key. The acknowledgment follows the enclosing transaction commit. An encryption or storage failure does not acknowledge the upload.

GET /v1/scopes/:id/recovery-keys returns metadata only. Historical keys from revoked enrollments remain labelled as such. Restores preserve encrypted records but quarantine scope authority and revoke grants/credentials; ordinary routes cannot reactivate them.

## Reveal

POST /v1/scopes/:id/recovery-keys/:keyId/reveal requires operator authentication, scope reveal/owner grant, an enabled escrow module and recent multifactor proof. Verified OIDC access-token auth_time must be within five minutes, with amr containing mfa or an acr value explicitly configured in OIDC_STEP_UP_ACRS. Configuration must use assurance values that the chosen identity provider actually guarantees. Development role tokens cannot satisfy this proof.

The request reason is one of device-recovery, key-verification or incident-response. The audit records identity, scope, record, device and reason; it excludes recovery material. The audit and reveal operation commit before a value is returned. HTTP replies use no-store. The console keeps the revealed value in component memory and hides it after 30 seconds, on scope/tab changes or on document visibility loss. It does not automatically copy keys into the clipboard or local storage.

This implementation has compiler feedback only. Transaction/audit failure, cryptographic tamper, keyring rotation, current IdP assurance claims, protected endpoint upload and actual recovery acceptance remain to be verified after the requested functionality is built.
