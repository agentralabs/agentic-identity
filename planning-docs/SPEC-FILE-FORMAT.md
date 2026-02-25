# SPEC-FILE-FORMAT.md

## .aid File Format

Magic: `AGID` (4 bytes)
Version: u32 (4 bytes)
Encrypted: bool (1 byte)

### Unencrypted Structure
```
[AGID][version][0x00][identity_document_json]
```

### Encrypted Structure
```
[AGID][version][0x01][salt:32][nonce:24][encrypted_data]
```

Encryption: ChaCha20-Poly1305
KDF: Argon2id (m=65536, t=3, p=4)

### File Types
- `.aid` — Identity file (encrypted private key + public document)
- `.aid.pub` — Public identity document only (JSON)
- `.arec` — Receipt chain file
- `.atrust` — Trust grant file
- `.aexp` — Experience chain file
- `.aspawn` — Spawn record file

### Storage Paths
```
~/.agentic-identity/
├── identities/
│   ├── {identity_id}.aid
│   └── {identity_id}.aid.pub
├── receipts/
│   └── {identity_id}/
│       └── {chain_position}.arec
├── trust/
│   ├── granted/
│   └── received/
├── experience/
│   └── {identity_id}/
├── spawn/
│   ├── children/
│   └── parents/
└── config.json
```
