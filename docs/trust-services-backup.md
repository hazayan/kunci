# Trust Services Backup

`kunci-server` is expected to run on the same trust-services host as Knox for
the first production deployment. Sharing the same physical TrustKey is
operationally useful, but each service must use separate FIDO2 credentials and
metadata.

Recommended primary host layout:

```text
identity-a
  kunci-server
    /usr/local/etc/kunci/fido2-credential.json
    /var/db/kunci-server/keys
  knox-server
    /usr/local/etc/knox/fido2-credential.json
    /var/db/knox
```

The same TrustKey device may hold both credentials, but kunci and Knox should
not share RP IDs, salts, metadata files, or backup credentials.

## Kunci Backup

Kunci already supports FIDO2-wrapped encrypted admin backups. The backup command
asks the running server to export its in-memory Tang key store as an encrypted
artifact over the local admin socket. The client should never receive plaintext
JWK material.

Use a backup credential distinct from the normal server-start credential:

```sh
kunci-server key fido2-enroll \
  --metadata-file /usr/local/etc/kunci/backup-fido2-credential.json \
  --rp-id identity-a-kunci-backup \
  --device auto \
  --pin-file /run/kunci/backup-fido2.pin

kunci backup-keys \
  --admin-sock /var/run/kunci-admin.sock \
  --backend fido2 \
  --fido2-metadata-file /usr/local/etc/kunci/backup-fido2-credential.json \
  --fido2-device auto \
  --fido2-pin-file /run/kunci/backup-fido2.pin \
  --output kunci-server-keys.kunci-backup
```

Store the encrypted backup artifact off the primary host. Store the backup
credential metadata with the restore procedure; it is not sufficient on its own
to decrypt the artifact, but it is required for the FIDO2 hmac-secret flow.

## Restore Drill

The restore target should be a backup trust-services host or a disposable VM:

```sh
kunci-server key restore \
  --input kunci-server-keys.kunci-backup \
  --backend fido2 \
  --directory /var/db/kunci-server/keys \
  --fido2-metadata-file /usr/local/etc/kunci/fido2-credential.json \
  --fido2-device auto \
  --fido2-pin-file /run/kunci/fido2.pin

kunci-server key unlock-test \
  --backend fido2 \
  --directory /var/db/kunci-server/keys \
  --fido2-metadata-file /usr/local/etc/kunci/fido2-credential.json \
  --fido2-device auto \
  --fido2-pin-file /run/kunci/fido2.pin
```

The restore drill is complete only when a restored `kunci-server` can answer a
client decrypt/unlock flow against a test binding. A bundle restore that merely
creates files is not enough evidence.

## Operational Notes

- FIDO2 protects the key store at rest. The running server still holds usable
  key material in memory.
- Losing the authenticator used for the active keystore requires a working
  encrypted backup and a restore credential.
- Prefer a second physical authenticator for backup artifacts when one is
  available.
- Kha should model the service configuration, backup artifact paths, and restore
  drill hooks, but not create a parallel secret encryption scheme.
